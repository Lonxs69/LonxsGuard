#!/usr/bin/env python3
"""
LonxsGuard — Toolkit de consola para auditoría de redes con captive portal / login.

Menú navegable (↑/↓, Enter) al estilo de las herramientas de Kali, pero nativo
en macOS y sin dependencias externas (solo librería estándar + nmap + tcpdump).

USO EXCLUSIVO en redes propias o con autorización explícita (CTF/hackathon).
Interceptar tráfico de terceros fuera del alcance autorizado NO es parte del reto.
"""

import curses
import datetime as dt
import html
import json
import math
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
import base64
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

VERSION = "1.0"
AUTHOR = "lonxs69"

# ---------------------------------------------------------------------------
# Colores ANSI (para la salida de los módulos, fuera de curses)
# ---------------------------------------------------------------------------
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"
    BOLD = "\033[1m"; END = "\033[0m"

SEV_COLOR = {"CRITICAL": C.R + C.BOLD, "HIGH": C.R, "MEDIUM": C.Y,
             "LOW": C.B, "INFO": C.CY}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

BANNER = r"""
  _                           ____                     _
 | |    ___  _ __ __  _____  / ___|_   _  __ _ _ __ __| |
 | |   / _ \| '_ \\ \/ / __|| |  _| | | |/ _` | '__/ _` |
 | |__| (_) | | | |>  <\__ \| |_| | |_| | (_| | | | (_| |
 |_____\___/|_| |_/_/\_\___/ \____|\__,_|\__,_|_|  \__,_|
"""


def sh(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _ssid(iface):
    out = sh(["ipconfig", "getsummary", iface])
    m = re.search(r"\bSSID\s*:\s*(.+)", out)
    if m:
        return m.group(1).strip()
    out = sh(["networksetup", "-getairportnetwork", iface])
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
    return m.group(1).strip() if m else "(desconocido)"


# ---------------------------------------------------------------------------
# Intro con logo RGB (truecolor) + bienvenida
# ---------------------------------------------------------------------------
def _rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"


def _hsv(h, s, v):
    i = int(h * 6) % 6
    f = h * 6 - int(h * 6)
    p, q, t = v * (1 - s), v * (1 - f * s), v * (1 - (1 - f) * s)
    r, g, b = [(v, t, p), (q, v, p), (p, v, t),
               (p, q, v), (t, p, v), (v, p, q)][i]
    return int(r * 255), int(g * 255), int(b * 255)


def _center(s, w, pad_extra=0):
    return " " * max(0, (w - len(s) - pad_extra) // 2) + s


def intro():
    cols = shutil.get_terminal_size((80, 24)).columns
    logo = BANNER.strip("\n").split("\n")
    lw = max(len(l) for l in logo)
    sys.stdout.write("\033[2J\033[H")   # limpiar
    try:
        frames = 20
        for fr in range(frames):
            sys.stdout.write("\033[H\n")
            off = fr / frames
            for ln in logo:
                pad = " " * max(0, (cols - lw) // 2)
                buf = pad
                for j, ch in enumerate(ln):
                    if ch == " ":
                        buf += " "
                        continue
                    r, g, b = _hsv(((j / lw) + off) % 1.0, 0.85, 1.0)
                    buf += _rgb(r, g, b) + ch
                sys.stdout.write(buf + "\033[0m\033[K\n")
            sys.stdout.flush()
            time.sleep(0.045)
    except Exception:
        for ln in logo:
            print(_center(ln, cols))
    gold = _rgb(255, 215, 0)
    w1 = "👑  Bienvenido, señor Junior  👑"
    print("\n" + gold + "\033[1m" + _center(w1, cols, pad_extra=2) + "\033[0m")
    sub = "hoy le demostraré por qué es tan valioso haberme construido, señor"
    print("\033[2m\033[3m" + _center(sub, cols) + "\033[0m\n")
    tag = f"LonxsGuard v{VERSION}  ·  by {AUTHOR}  ·  solo redes autorizadas"
    print(_rgb(130, 140, 170) + _center(tag, cols) + "\033[0m")
    try:
        input("\n" + _center("Presiona Enter para entrar...", cols))
    except EOFError:
        pass


# ---------------------------------------------------------------------------
# Estado de la sesión (persiste entre módulos)
# ---------------------------------------------------------------------------
class State:
    def __init__(self):
        self.net = {}
        self.findings = []
        self.hosts = []
        self.captures = []   # cabeceras/credenciales interceptadas
        self.iface = "en0"

    def add(self, sev, title, detail, reco=""):
        self.findings.append({"sev": sev, "title": title,
                              "detail": detail, "reco": reco})
        color = SEV_COLOR.get(sev, C.W)
        print(f"  {color}[{sev}]{C.END} {title}")
        if detail:
            print(f"      {C.DIM}{detail}{C.END}")

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEV_RANK.get(f["sev"], 9))


# ===========================================================================
# MÓDULO 1 — Detección de red
# ===========================================================================
def m_detect(st):
    iface = st.iface
    print(f"{C.BOLD}[1] Detección de red ({iface}){C.END}\n")

    def g_ssid():
        out = sh(["ipconfig", "getsummary", iface])
        m = re.search(r"\bSSID\s*:\s*(.+)", out)
        if m: return m.group(1).strip()
        out = sh(["networksetup", "-getairportnetwork", iface])
        m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
        return m.group(1).strip() if m else "(desconocido)"

    ip = sh(["ipconfig", "getifaddr", iface])
    ifc = sh(["ifconfig", iface])
    maskm = re.search(r"netmask (0x[0-9a-fA-F]+)", ifc)
    mask = ""
    if maskm:
        hx = int(maskm.group(1), 16)
        mask = ".".join(str((hx >> s) & 0xFF) for s in (24, 16, 8, 0))
    gw = ""
    g = sh(["route", "-n", "get", "default"])
    gm = re.search(r"gateway:\s*([\d.]+)", g)
    if gm: gw = gm.group(1)
    dns = []
    for s in re.findall(r"nameserver\[\d+\]\s*:\s*([\d.]+)", sh(["scutil", "--dns"])):
        if s not in dns: dns.append(s)
    macm = re.search(r"ether ([0-9a-f:]{17})", ifc)
    cidr = ""
    if ip and mask:
        octs = [int(x) for x in ip.split(".")]
        mb = [int(x) for x in mask.split(".")]
        net = ".".join(str(octs[i] & mb[i]) for i in range(4))
        bits = sum(bin(int(o)).count("1") for o in mask.split("."))
        cidr = f"{net}/{bits}"

    st.net = {"ssid": g_ssid(), "iface": iface, "ip": ip, "mask": mask,
              "cidr": cidr, "gateway": gw, "dns": dns,
              "mac": macm.group(1) if macm else "",
              "ts": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    print(f"  SSID     : {C.G}{st.net['ssid']}{C.END}")
    print(f"  MAC local: {st.net['mac']}")
    print(f"  IP local : {ip}   máscara {mask}  → red {C.G}{cidr or '?'}{C.END}")
    print(f"  Gateway  : {gw or '?'}")
    print(f"  DNS      : {', '.join(dns) if dns else '(ninguno)'}")
    if not ip:
        print(f"\n  {C.Y}Sin IP: ¿asociado a la red?{C.END}")


# ===========================================================================
# MÓDULO 2 — Auditoría de captive portal
# ===========================================================================
APPLE_PROBE = "http://captive.apple.com/hotspot-detect.html"
APPLE_OK = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"


def http_probe(url, timeout=6):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CaptiveNetworkSupport/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.geturl(), r.read(30000).decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, url, "", dict(e.headers or {})
    except Exception as e:
        return None, url, f"__ERR__ {e}", {}


# Sondas de varios SO: si el portal deja pasar una, otra lo delata.
CANARIES = [
    ("Apple", "http://captive.apple.com/hotspot-detect.html", "Success"),
    ("Android", "http://connectivitycheck.gstatic.com/generate_204", None),  # espera 204
    ("Microsoft", "http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"),
]


def detect_portal_multi():
    """Devuelve (captive, portal_url, evidencia[(sonda, resultado)])."""
    captive, portal, ev = False, None, []
    for name, url, expect in CANARIES:
        s, u, b, h = http_probe(url)
        if s is None:
            ev.append((name, "sin respuesta"))
            continue
        ok = (s == 204) if expect is None else (expect in (b or ""))
        if ok:
            ev.append((name, "OK · salida libre"))
        else:
            captive = True
            cand = (u if u != url else (h or {}).get("Location")) or url
            portal = portal or cand
            ev.append((name, f"interceptado → {cand}"))
    return captive, portal, ev


def m_portal(st):
    if not st.net:
        m_detect(st); print()
    print(f"{C.BOLD}[2] Auditoría de captive portal / login{C.END}\n")
    captive, portal_url, evidence = detect_portal_multi()
    for name, res in evidence:
        tag = C.G if "OK" in res else (C.Y if "interceptado" in res else C.DIM)
        print(f"  {C.DIM}sonda{C.END} {name:<10} {tag}{res}{C.END}")
    print()

    if not captive:
        print(f"  {C.G}Sin captive portal activo (o ya autenticado).{C.END}")
        st.net["portal"] = None
    else:
        st.net["portal"] = portal_url
        print(f"  {C.Y}Captive portal detectado{C.END} → {portal_url}\n")
        if portal_url and portal_url.startswith("http://"):
            st.add("HIGH", "Portal/login sobre HTTP (sin cifrar)",
                   f"{portal_url} responde en texto plano; credenciales sin TLS.",
                   "Servir portal y POST de login solo por HTTPS + HSTS.")
        if portal_url:
            _, purl, pbody, _ = http_probe(portal_url)
            _analyze_form(st, purl, pbody)

    _preauth_leak(st, captive)
    _dns_egress(st, captive)
    if captive:
        st.add("INFO", "Posible autenticación por MAC",
               "Si el portal recuerda al cliente por MAC, se puede clonar una MAC "
               "ya autorizada (probar en lab: sudo ifconfig en0 ether <MAC>).",
               "Atar la sesión a cookie/certificado, no solo a la MAC.")


def _analyze_form(st, url, body):
    if not body or body.startswith("__ERR__"):
        return
    for f in re.findall(r"<form[^>]*>", body, re.I):
        action = re.search(r'action\s*=\s*["\']([^"\']+)', f, re.I)
        method = re.search(r'method\s*=\s*["\']([^"\']+)', f, re.I)
        action = action.group(1) if action else "(misma URL)"
        method = (method.group(1) if method else "GET").upper()
        if method == "GET" and re.search(r"pass|clave|pwd", body, re.I):
            st.add("HIGH", "Login por GET con contraseña",
                   f"method=GET action={action}: la clave queda en URL/logs.",
                   "Enviar credenciales por POST sobre HTTPS.")
        if action.startswith("http://"):
            st.add("MEDIUM", "Formulario envía a endpoint HTTP",
                   f"action={action} sin TLS.", "El action debe ser HTTPS.")
    pw = len(re.findall(r'type\s*=\s*["\']password', body, re.I))
    if pw:
        print(f"  {C.DIM}Formulario con {pw} campo(s) de contraseña detectado.{C.END}")


def _preauth_leak(st, captive):
    leaked = []
    for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53)]:
        try:
            socket.create_connection((host, port), timeout=4).close()
            leaked.append(f"{host}:{port}")
        except Exception:
            pass
    if captive and leaked:
        st.add("CRITICAL", "Fuga de conectividad antes de autenticar",
               f"Sin pasar el portal se alcanzó {', '.join(leaked)} directo: "
               "el control de acceso es evadible.",
               "Bloquear TODO el egress de clientes no autenticados, no solo HTTP.")
    elif captive:
        print(f"  {C.DIM}Sin fuga directa pre-auth (bien).{C.END}")


def _dns_egress(st, captive):
    gw = st.net.get("gateway", "")
    for srv in (st.net.get("dns") or []) + ([gw] if gw else []):
        out = sh(["dig", "+time=3", "+tries=1", "+short", f"@{srv}", "example.com"])
        if re.search(r"\d+\.\d+\.\d+\.\d+", out):
            if captive:
                st.add("HIGH", "DNS externo resoluble pre-auth (túnel DNS)",
                       f"{srv} resuelve dominios externos sin autenticar: "
                       "canal para túnel DNS (internet gratis / exfiltración).",
                       "Restringir DNS pre-auth solo a los dominios del portal.")
            return
    if captive:
        print(f"  {C.DIM}DNS externo no resoluble pre-auth (bien).{C.END}")


# ===========================================================================
# MÓDULO 3 — Interceptor de cabeceras HTTP (tcpdump)
# ===========================================================================
def m_sniff(st):
    iface = st.iface
    print(f"{C.BOLD}[3] Interceptor de cabeceras HTTP{C.END}")
    print(f"  {C.DIM}Captura tráfico HTTP en {iface} y extrae peticiones, "
          f"cookies, credenciales y fechas.{C.END}")
    print(f"  {C.Y}Requiere sudo. Solo sobre la red AUTORIZADA del reto.{C.END}\n")
    try:
        dur = input("  Duración de la captura en segundos [30]: ").strip()
        dur = int(dur) if dur else 30
    except (ValueError, EOFError):
        dur = 30

    ports = "tcp port 80 or tcp port 8080 or tcp port 8000"
    cmd = ["sudo", "tcpdump", "-i", iface, "-s", "0", "-A", "-l", "-n", ports]
    print(f"\n  Capturando {dur}s... (Ctrl-C para parar antes)\n")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        print(f"  {C.R}No se pudo iniciar tcpdump: {e}{C.END}")
        return

    deadline = time.time() + dur
    found = 0
    try:
        while time.time() < deadline:
            rlist, _, _ = select.select([proc.stdout], [], [], 0.5)
            if not rlist:
                continue
            line = proc.stdout.readline()
            if not line:
                break
            hit = _parse_http_line(st, line)
            if hit:
                found += 1
    except KeyboardInterrupt:
        print(f"\n  {C.DIM}Captura detenida por el usuario.{C.END}")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
    if found:
        print(f"\n  {C.G}{found} evento(s) de interés capturado(s).{C.END} "
              f"Analízalos en el módulo [4].")
    else:
        print(f"\n  {C.Y}0 eventos: normal si el tráfico va por HTTPS (443) o si solo "
              f"ves tu propio tráfico.{C.END}")
        print(f"  {C.DIM}El sniffer es PASIVO: solo captura lo que ya circula en HTTP. "
              f"Para forzar captura, usa el Inspector [8] o el Modo Misión [1], que "
              f"golpean el portal activamente y sí traen cookies/cabeceras.{C.END}")


def _parse_http_line(st, line):
    s = line.strip()
    hit = False
    patterns = [
        ("request", r"^(GET|POST|PUT|HEAD|DELETE)\s+(\S+)\s+HTTP"),
        ("host", r"^Host:\s*(.+)"),
        ("cookie", r"^Cookie:\s*(.+)"),
        ("setcookie", r"^Set-Cookie:\s*(.+)"),
        ("auth", r"^Authorization:\s*(.+)"),
        ("date", r"^(?:Date|Last-Modified):\s*(.+)"),
    ]
    for kind, pat in patterns:
        m = re.search(pat, s, re.I)
        if m:
            val = m.group(0)
            st.captures.append({"kind": kind, "value": val, "raw": s})
            color = {"cookie": C.M, "setcookie": C.M, "auth": C.R,
                     "date": C.CY, "request": C.G}.get(kind, C.W)
            print(f"  {color}{val[:160]}{C.END}")
            hit = True
    # credenciales en cuerpo de formulario
    for m in re.finditer(r"(user(?:name)?|usuario|email|login|pass(?:word)?|clave|pwd)=([^&\s\"']+)",
                         s, re.I):
        st.captures.append({"kind": "cred", "value": m.group(0), "raw": s})
        print(f"  {C.R}{C.BOLD}[CRED] {m.group(0)}{C.END}")
        hit = True
    return hit


# ===========================================================================
# MÓDULO 4 — Análisis de cookies / JWT (decodifica fechas → flags)
# ===========================================================================
def _b64pad(s):
    return s + "=" * (-len(s) % 4)


