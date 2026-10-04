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


def _try_decode(token):
    """Intenta JWT y base64 simple; devuelve texto decodificado si parece útil."""
    out = []
    # JWT: tres partes separadas por punto
    if token.count(".") == 2:
        for part in token.split(".")[:2]:
            try:
                dec = base64.urlsafe_b64decode(_b64pad(part)).decode("utf-8", "replace")
                if "{" in dec:
                    out.append("JWT: " + dec)
            except Exception:
                pass
    # base64 plano
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", token):
        try:
            dec = base64.b64decode(_b64pad(token)).decode("utf-8", "replace")
            if sum(c.isprintable() for c in dec) > len(dec) * 0.8 and any(c.isalnum() for c in dec):
                out.append("b64: " + dec)
        except Exception:
            pass
    return out


def m_cookies(st):
    print(f"{C.BOLD}[4] Análisis de cookies / sesión{C.END}\n")
    cookies = [c for c in st.captures if c["kind"] in ("cookie", "setcookie")]
    if not cookies:
        print(f"  {C.Y}No hay cookies capturadas. Usa antes el módulo [3] o [6].{C.END}")
        return

    for c in cookies:
        line = c["value"]
        print(f"  {C.M}{line[:200]}{C.END}")
        # flags de seguridad en Set-Cookie
        if c["kind"] == "setcookie":
            low = line.lower()
            if "secure" not in low:
                st.add("MEDIUM", "Cookie sin flag Secure",
                       line[:80], "Marcar la cookie como Secure (solo HTTPS).")
            if "httponly" not in low:
                st.add("LOW", "Cookie sin flag HttpOnly",
                       line[:80], "Marcar HttpOnly para mitigar robo vía XSS.")
        # intentar decodificar cada valor
        for kv in re.findall(r"([A-Za-z0-9_\-]+)=([A-Za-z0-9+/=._-]+)", line):
            for dec in _try_decode(kv[1]):
                print(f"      {C.CY}↳ {kv[0]} → {dec[:200]}{C.END}")
                # buscar timestamps dentro
                _hunt_timestamp(st, dec, origen=kv[0])


def _hunt_timestamp(st, text, origen=""):
    # epoch (10 dígitos) o fechas ISO
    for ts in re.findall(r"\b(1[0-9]{9})\b", text):
        try:
            when = dt.datetime.fromtimestamp(int(ts))
            print(f"        {C.Y}⏱ epoch {ts} = {when:%Y-%m-%d %H:%M:%S}{C.END}")
        except Exception:
            pass
    for iso in re.findall(r"\b(20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", text):
        print(f"        {C.Y}⏱ fecha {iso}{C.END}")


# ===========================================================================
# MÓDULO 5 — Enumeración de hosts y puertos (nmap)
# ===========================================================================
def m_enum(st):
    if not st.net:
        m_detect(st); print()
    print(f"{C.BOLD}[5] Enumeración de hosts y puertos{C.END}\n")
    cidr = st.net.get("cidr")
    if not cidr:
        print(f"  {C.Y}Sin subred válida.{C.END}"); return
    print(f"  {C.Y}nmap barrerá {cidr}. Solo en red AUTORIZADA.{C.END}")
    if input("  ¿Continuar? [s/N] ").strip().lower() != "s":
        print("  Cancelado."); return

    print(f"\n  Descubriendo hosts vivos...")
    out = sh(["nmap", "-sn", "-T4", cidr], timeout=120)
    hosts = []
    for block in re.split(r"\nNmap scan report for ", out):
        ipm = re.search(r"([\d.]+)", block)
        if not ipm or "Starting Nmap" in block.split("\n")[0]:
            if not ipm: continue
        if not ipm: continue
        ip = ipm.group(1)
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip): continue
        macm = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})\s*\(([^)]*)\)", block)
        hosts.append({"ip": ip, "mac": macm.group(1) if macm else "",
                      "vendor": macm.group(2) if macm else "", "ports": []})
    st.hosts = hosts
    print(f"  {C.G}{len(hosts)} host(s) vivo(s):{C.END}")
    for h in hosts:
        tag = f"    {h['ip']:<16}"
        if h["vendor"]: tag += f" {C.DIM}{h['vendor']}{C.END}"
        if h["ip"] == st.net.get("gateway"): tag += f"  {C.Y}← gateway/portal{C.END}"
        print(tag)

    targets = [h for h in hosts if h["ip"] != st.net.get("ip")]
    if not targets: return
    print(f"\n  Escaneando puertos (top-100 + versión)...")
    risky = {"telnet": ("HIGH", "Telnet (texto plano)"),
             "ftp": ("MEDIUM", "FTP"), "http": ("LOW", "HTTP sin cifrar"),
             "microsoft-ds": ("MEDIUM", "SMB"), "ms-wbt-server": ("MEDIUM", "RDP"),
             "vnc": ("HIGH", "VNC")}
    for h in targets:
        out = sh(["nmap", "-F", "-sV", "--version-light", "-T4", h["ip"]], timeout=180)
        for line in out.splitlines():
            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if m:
                h["ports"].append({"port": m.group(1), "proto": m.group(2),
                                   "service": m.group(3), "version": m.group(4).strip()})
        if h["ports"]:
            print(f"    {h['ip']:<16} " +
                  ", ".join(f"{p['port']}/{p['service']}" for p in h["ports"]))
            for p in h["ports"]:
                if p["service"] in risky:
                    sev, t = risky[p["service"]]
                    st.add(sev, f"{t} en {h['ip']}",
                           f"Puerto {p['port']} ({p['version'] or p['service']}).",
                           "Cerrar/segmentar/cifrar el servicio.")


# ===========================================================================
# MÓDULO 6 — Inspector de peticiones HTTP (replay manual)
# ===========================================================================
def m_http(st):
    print(f"{C.BOLD}[6] Inspector de peticiones HTTP{C.END}\n")
    url = input("  URL (ej. http://portal.local/login): ").strip()
    if not url:
        print("  Cancelado."); return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    status, final, body, headers = http_probe(url, timeout=8)
    print(f"\n  {C.G}Status:{C.END} {status}   {C.G}URL final:{C.END} {final}\n")
    print(f"  {C.BOLD}Cabeceras de respuesta:{C.END}")
    for k, v in headers.items():
        color = C.M if k.lower() == "set-cookie" else (C.CY if k.lower() in ("date", "last-modified") else C.W)
        print(f"    {color}{k}: {v}{C.END}")
        if k.lower() == "set-cookie":
            st.captures.append({"kind": "setcookie", "value": f"Set-Cookie: {v}", "raw": v})
            for kv in re.findall(r"([A-Za-z0-9_\-]+)=([A-Za-z0-9+/=._-]+)", v):
                for dec in _try_decode(kv[1]):
                    print(f"      {C.CY}↳ {kv[0]} → {dec[:160]}{C.END}")
                    _hunt_timestamp(st, dec, kv[0])
    # título / formulario
    tm = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    if tm:
        print(f"\n  {C.DIM}<title>: {tm.group(1).strip()[:80]}{C.END}")
    _analyze_form(st, final, body)


# ===========================================================================
# MÓDULO 7 — Reporte HTML
# ===========================================================================
def m_report(st):
    print(f"{C.BOLD}[7] Generar reporte HTML{C.END}\n")
    n = st.net or {}
    esc = lambda x: html.escape(str(x))
    counts = {}
    for f in st.findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    cards = ""
    for f in st.sorted_findings():
        cards += (f'<div class="fd {f["sev"]}">'
                  f'<div class="fh"><span class="bdg {f["sev"]}">{f["sev"]}</span>'
                  f'<span class="ft">{esc(f["title"])}</span></div>'
                  f'<div class="fdet">{esc(f["detail"])}</div>'
                  + (f'<div class="frec">✔ {esc(f["reco"])}</div>' if f["reco"] else "")
                  + "</div>")
    hrows = ""
    for h in st.hosts:
        pc = "".join(f'<span class="pc">{esc(p["port"])}/{esc(p["service"])}</span>'
                     for p in h["ports"]) or '<span class="mut">—</span>'
        gw = ' <span class="gw">gateway</span>' if h["ip"] == n.get("gateway") else ""
        hrows += (f'<tr><td class="mono">{esc(h["ip"])}{gw}</td>'
                  f'<td>{esc(h["vendor"]) or "—"}</td><td>{pc}</td></tr>')
    caps = ""
    for c in st.captures:
        caps += (f'<div class="cap"><span class="kc">{esc(c["kind"])}</span>'
                 f'<code>{esc(c["value"][:280])}</code></div>')
    flags = collect_flags(st)
    flag_items = "".join(
        f'<li class="{k}"><b>{"🚩" if k == "flag" else "⏱"}</b> {esc(v)}</li>'
        for k, v in flags)
    total = len(st.findings)
    segs = ""
    if total:
        for s in order:
            cnt = counts.get(s, 0)
            if cnt:
                segs += f'<span class="seg {s}" style="flex:{cnt}"></span>'
    else:
        segs = '<span class="seg EMPTY" style="flex:1"></span>'
    legend = "".join(f'<span class="lg"><i class="dot {s}"></i>{s}·{counts.get(s,0)}</span>'
                     for s in order)

    def tile(num, lab, cls=""):
        return (f'<div class="kpi {cls}"><div class="kn" data-target="{num}">0</div>'
                f'<div class="kl">{lab}</div></div>')
    kpis = (tile(total, "Hallazgos")
            + tile(counts.get("CRITICAL", 0), "Críticos", "crit")
            + tile(counts.get("HIGH", 0), "Altos", "danger")
            + tile(len(st.captures), "Capturas")
            + tile(len(flags), "Flags", "flag"))

    segs = ""
    if total:
        for s in order:
            cnt = counts.get(s, 0)
            if cnt:
                segs += f'<span class="seg {s}" style="--w:{cnt / total * 100:.1f}%"></span>'
    else:
        segs = '<span class="seg EMPTY" style="--w:100%"></span>'

    CSS = r"""
*{box-sizing:border-box}
:root{--bg:#05080e;--bg2:#0a0f1a;--panel:#0b111c;--bd:rgba(0,255,156,.15);--bd2:rgba(0,255,156,.55);
--tx:#d6f5e4;--mut:#6f8a86;--grn:#00ff9c;--cy:#22d3ee;--vi:#a855f7;--ok:#00ff9c;
--CRITICAL:#ff4d61;--HIGH:#ff8c42;--MEDIUM:#ffd23d;--LOW:#4da6ff;--INFO:#22d3ee}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--tx);min-height:100vh;font-size:14px;line-height:1.6;
font-family:ui-monospace,SFMono-Regular,Menlo,"Cascadia Code","Courier New",monospace}
.aurora{position:fixed;inset:0;z-index:0;overflow:hidden;pointer-events:none}
.aurora span{position:absolute;width:46vw;height:46vw;border-radius:50%;opacity:.13;will-change:transform;
background:radial-gradient(circle,var(--grn),transparent 62%);top:-12vh;left:-10vw;animation:drift 30s ease-in-out infinite}
.aurora span:nth-child(2){background:radial-gradient(circle,var(--cy),transparent 62%);
left:auto;right:-12vw;top:40vh;animation-duration:38s;animation-direction:reverse}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(9vw,7vh) scale(1.2)}}
.scan{position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.5;
background:repeating-linear-gradient(0deg,transparent 0,transparent 2px,rgba(0,255,156,.022) 3px)}
@media(prefers-reduced-motion:reduce){.aurora span{animation:none}.cur{animation:none}}
.wrap{position:relative;z-index:2;max-width:940px;margin:0 auto;padding:26px 18px 72px}
.term{background:linear-gradient(180deg,var(--panel),var(--bg2));border:1px solid var(--bd);border-radius:12px;
overflow:hidden;box-shadow:0 12px 44px rgba(0,0,0,.55),0 0 24px rgba(0,255,156,.05)}
.termbar{display:flex;align-items:center;gap:7px;padding:11px 14px;border-bottom:1px solid var(--bd);background:rgba(0,255,156,.03)}
.tdot{width:11px;height:11px;border-radius:50%}.tdot.r{background:#ff5f57}.tdot.y{background:#febc2e}.tdot.g{background:#28c840}
.termttl{margin-left:10px;color:var(--mut);font-size:.78rem}
.termbody{padding:20px 22px}
.cmd{color:var(--mut);font-size:.84rem}.cmd b{color:var(--grn);font-weight:600}.cmd i{color:var(--cy);font-style:normal}
h1{margin:8px 0 2px;font-size:1.5rem;color:var(--grn);letter-spacing:.5px;text-shadow:0 0 18px rgba(0,255,156,.4)}
.cur{display:inline-block;width:9px;height:1.02em;background:var(--grn);vertical-align:-2px;margin-left:4px;animation:blink 1.1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.sub{color:var(--mut);font-size:.84rem;margin-top:7px}.sub b{color:var(--cy);font-weight:600}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}
.kpi{background:var(--panel);border:1px solid var(--bd);border-radius:12px;padding:16px 12px;text-align:center;transition:transform .16s,border-color .16s,box-shadow .16s}
.kpi:hover{transform:translateY(-4px);border-color:var(--bd2);box-shadow:0 0 22px rgba(0,255,156,.13)}
.kpi .kn{font-size:1.85rem;font-weight:700;color:var(--grn);line-height:1}
.kpi .kl{color:var(--mut);font-size:.64rem;text-transform:uppercase;letter-spacing:1px;margin-top:8px}
.kpi.crit .kn{color:var(--CRITICAL)}.kpi.danger .kn{color:var(--HIGH)}.kpi.flag .kn{color:var(--ok)}
h2{font-size:.95rem;margin:28px 0 12px;color:var(--grn);letter-spacing:.5px}
h2::before{content:"// ";color:var(--mut)}
.panel{background:var(--panel);border:1px solid var(--bd);border-radius:12px;padding:18px 20px;margin:12px 0}
.panel>h3{margin:0 0 13px;font-size:.82rem;color:var(--cy);text-transform:uppercase;letter-spacing:.8px}
.bar{display:flex;height:16px;border-radius:8px;overflow:hidden;background:#060b13;border:1px solid var(--bd)}
.seg{width:0;transition:width 1s cubic-bezier(.2,.8,.2,1)}.bar.filled .seg{width:var(--w)}
.seg.CRITICAL{background:var(--CRITICAL)}.seg.HIGH{background:var(--HIGH)}.seg.MEDIUM{background:var(--MEDIUM)}
.seg.LOW{background:var(--LOW)}.seg.INFO{background:var(--INFO)}.seg.EMPTY{background:#15241c}
.legend{display:flex;flex-wrap:wrap;gap:15px;margin-top:13px;font-size:.78rem;color:var(--mut)}
.lg .dot,.dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px}
.dot.CRITICAL{background:var(--CRITICAL)}.dot.HIGH{background:var(--HIGH)}.dot.MEDIUM{background:var(--MEDIUM)}
.dot.LOW{background:var(--LOW)}.dot.INFO{background:var(--INFO)}
.meta{display:grid;grid-template-columns:auto 1fr auto 1fr;gap:11px 22px;font-size:.86rem}
.meta b{color:var(--grn);font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.6px}
.mono{color:var(--cy)}
.flags{border-color:rgba(0,255,156,.5);box-shadow:0 0 26px rgba(0,255,156,.14)}
.flags ul{list-style:none;margin:0;padding:0}
.flags li{padding:11px 13px;border-radius:9px;margin:7px 0;background:#060b13;border:1px solid var(--bd);
font-size:.84rem;word-break:break-all;color:var(--grn)}
.flags li.flag{border-left:3px solid var(--CRITICAL)}.flags li.date{border-left:3px solid var(--MEDIUM);color:var(--MEDIUM)}
.fd{background:#060b13;border:1px solid var(--bd);border-left:3px solid var(--mut);border-radius:10px;
padding:14px 16px;margin:10px 0;transition:transform .16s,border-color .16s}
.fd:hover{transform:translateX(5px);border-color:var(--bd2)}
.fd.CRITICAL{border-left-color:var(--CRITICAL)}.fd.HIGH{border-left-color:var(--HIGH)}
.fd.MEDIUM{border-left-color:var(--MEDIUM)}.fd.LOW{border-left-color:var(--LOW)}.fd.INFO{border-left-color:var(--INFO)}
.fh{display:flex;align-items:center;gap:11px}.ft{font-weight:700;color:var(--tx)}
.fdet{color:var(--mut);font-size:.86rem;margin-top:7px}.frec{color:var(--grn);font-size:.82rem;margin-top:7px}
.frec::before{content:"$ fix: ";color:var(--mut)}
.bdg{border-radius:5px;padding:2px 9px;font-size:.64rem;font-weight:800;color:#05080e;letter-spacing:.5px}
.bdg.CRITICAL{background:var(--CRITICAL)}.bdg.HIGH{background:var(--HIGH)}.bdg.MEDIUM{background:var(--MEDIUM)}
.bdg.LOW{background:var(--LOW);color:#fff}.bdg.INFO{background:var(--INFO)}
.cap{display:flex;gap:11px;align-items:flex-start;padding:9px 0;border-bottom:1px solid var(--bd)}
.cap:last-child{border-bottom:none}
.kc{flex:0 0 auto;font-size:.62rem;text-transform:uppercase;letter-spacing:.5px;background:rgba(0,255,156,.1);color:var(--grn);border-radius:4px;padding:3px 8px;font-weight:700}
.cap code{color:var(--cy);font-size:.8rem;word-break:break-all}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px 8px;border-bottom:1px solid var(--bd)}
th{color:var(--grn);font-size:.7rem;text-transform:uppercase;letter-spacing:.6px}
.pc{display:inline-block;background:rgba(34,211,238,.1);color:var(--cy);border-radius:5px;padding:2px 9px;margin:2px;font-size:.76rem}
.gw{background:var(--vi);color:#fff;border-radius:4px;padding:1px 8px;font-size:.62rem;font-weight:700}
.mut{color:var(--mut)}.empty{color:var(--mut);padding:8px 0}
footer{color:var(--mut);text-align:center;font-size:.76rem;margin-top:36px;padding-top:20px;border-top:1px solid var(--bd)}
footer b{color:var(--grn)}
@media(max-width:720px){.grid{grid-template-columns:repeat(2,1fr)}.meta{grid-template-columns:auto 1fr}h1{font-size:1.25rem}}
"""

    JS = r"""
document.querySelectorAll('.kn').forEach(function(el){var t=+(el.dataset.target||0),d=850,s=null;
function f(ts){if(!s)s=ts;var p=Math.min((ts-s)/d,1);el.textContent=Math.round(p*t);if(p<1)requestAnimationFrame(f);}requestAnimationFrame(f);});
requestAnimationFrame(function(){var b=document.querySelector('.bar');if(b)b.classList.add('filled');});
"""

    sec_flags = (f'<h2>flags y fechas detectadas [{len(flags)}]</h2>'
                 f'<div class="panel flags"><ul>{flag_items}</ul></div>') if flags else ""

    head = (f'<!doctype html><html lang="es"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>LonxsGuard — {esc(n.get("ssid",""))}</title><style>' + CSS + "</style></head>")

    body = f"""<body><div class="aurora"><span></span><span></span></div><div class="scan"></div><div class="wrap">
<div class="term">
<div class="termbar"><span class="tdot r"></span><span class="tdot y"></span><span class="tdot g"></span>
<span class="termttl">lonxsguard — security audit report</span></div>
<div class="termbody">
<div class="cmd"><b>lonxs69@lonxsguard</b>:~$ ./lonxsguard --report --target <i>{esc(n.get('ssid','—'))}</i></div>
<h1>Reporte de auditoría<span class="cur"></span></h1>
<div class="sub">red <b>{esc(n.get('ssid','—'))}</b> · {esc(n.get('cidr','—'))} · {esc(n.get('ts',''))} · <b>{total}</b> hallazgos · by {AUTHOR}</div>
</div></div>
<div class="grid">{kpis}</div>
<div class="panel"><h3>distribución de severidad</h3><div class="bar">{segs}</div><div class="legend">{legend}</div></div>
<div class="panel"><h3>objetivo</h3><div class="meta">
<b>SSID</b><span>{esc(n.get('ssid','—'))}</span><b>Red</b><span class="mono">{esc(n.get('cidr','—'))}</span>
<b>IP</b><span class="mono">{esc(n.get('ip','—'))}</span><b>Gateway</b><span class="mono">{esc(n.get('gateway','—'))}</span>
<b>Portal</b><span>{esc(n.get('portal') or 'ninguno / autenticado')}</span><b>DNS</b><span class="mono">{esc(', '.join(n.get('dns',[])) or '—')}</span>
</div></div>
{sec_flags}
<h2>hallazgos [{total}]</h2>
{cards or '<div class="panel"><div class="empty">Sin hallazgos registrados.</div></div>'}
<h2>interceptado [{len(st.captures)}]</h2>
<div class="panel">{caps or '<div class="empty">Nada capturado todavía.</div>'}</div>
<h2>hosts [{len(st.hosts)}]</h2>
<div class="panel"><table>
<tr><th>IP</th><th>Fabricante</th><th>Puertos</th></tr>{hrows or '<tr><td colspan=3 class="mut">Sin enumeración.</td></tr>'}</table></div>
<footer>LonxsGuard v{VERSION} · by <b>{AUTHOR}</b> · uso exclusivo en redes autorizadas</footer>
</div><script>""" + JS + "</script></body></html>"
    doc = head + body
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(outdir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9]+", "_", n.get("ssid", "red")).strip("_") or "red"
    path = os.path.join(outdir, f"lonxsguard_{safe}_{dt.datetime.now():%Y%m%d_%H%M%S}.html")
    with open(path, "w") as fh:
        fh.write(doc)
    print(f"  {C.G}Reporte guardado:{C.END} {path}")
    print(f"  {C.DIM}Abrir con:  open '{path}'{C.END}")
    if input("\n  ¿Abrir ahora? [s/N] ").strip().lower() == "s":
        subprocess.run(["open", path])


# ===========================================================================
# MÓDULO 0 — Ver redes cercanas (pasivo) y conectar
# ===========================================================================
def _parse_wifi(out):
    nets, in_en0, section, cur = [], False, None, None
    for ln in out.split("\n"):
        stripped = ln.strip()
        lead = len(ln) - len(ln.lstrip(" "))
        if lead == 8 and stripped.endswith(":"):
            in_en0 = (stripped == "en0:")
            section = cur = None
            continue
        if not in_en0:
            continue
        if lead == 10 and stripped.endswith(":"):
            if stripped.startswith("Current Network"):
                section = "current"
            elif stripped.startswith("Other Local"):
                section = "other"
            else:
                section = None
            cur = None
            continue
        if section and lead == 12 and stripped.endswith(":"):
            cur = {"ssid": stripped[:-1], "security": "?", "channel": "?",
                   "rssi": -100, "current": section == "current", "open": False}
            nets.append(cur)
            continue
        if cur and lead == 14 and ":" in stripped:
            k, _, v = stripped.partition(":")
            k, v = k.strip(), v.strip()
            if k == "Security":
                cur["security"] = v
                cur["open"] = ("none" in v.lower() or v.lower() == "open")
            elif k == "Channel":
                cur["channel"] = v.split()[0] if v else "?"
            elif k.startswith("Signal"):
                m = re.search(r"(-?\d+)", v)
                cur["rssi"] = int(m.group(1)) if m else -100
    return nets


def _bars(rssi):
    if rssi >= -55: return "▂▄▆█"
    if rssi >= -67: return "▂▄▆ "
    if rssi >= -78: return "▂▄  "
    return "▂   "


def m_scan(st):
    print(f"{C.BOLD}[0] Redes cercanas{C.END}")
    print(f"  {C.DIM}Escaneo pasivo (no requiere conectarse)...{C.END}\n")
    out = sh(["system_profiler", "SPAirPortDataType"], timeout=40)
    nets = _parse_wifi(out)
    if not nets:
        print(f"  {C.Y}No se listaron redes.{C.END}")
        print(f"  {C.DIM}En macOS reciente el escaneo necesita Localización activada "
              f"para tu terminal:\n  Ajustes del Sistema → Privacidad y seguridad → "
              f"Localización → activa Ghostty.{C.END}")
        return
    nets.sort(key=lambda n: n["rssi"], reverse=True)
    print(f"  {C.G}{len(nets)} red(es) detectada(s){C.END}  {C.DIM}(ordenadas por señal){C.END}\n")
    print(f"   {C.BOLD}{'#':<3}{'SSID':<26}{'Señal':<12}{'Canal':<7}Seguridad{C.END}")
    for i, n in enumerate(nets, 1):
        lock = "🔓" if n["open"] else "🔒"
        cur = f"  {C.G}← conectado{C.END}" if n["current"] else ""
        sig = f"{_bars(n['rssi'])} {n['rssi']}"
        print(f"   {i:<3}{n['ssid'][:24]:<26}{sig:<12}{n['channel']:<7}{lock} {n['security']}{cur}")
    try:
        sel = input(f"\n  Nº de red para intentar conectar (Enter = volver): ").strip()
    except EOFError:
        sel = ""
    if not sel.isdigit():
        print("  Volviendo al menú."); return
    idx = int(sel) - 1
    if not (0 <= idx < len(nets)):
        print("  Opción inválida."); return
    _connect(st, nets[idx])


def _connect(st, net):
    import getpass
    ssid = net["ssid"]
    print(f"\n  Intentando conectar a {C.G}{ssid}{C.END} "
          f"({'abierta' if net['open'] else net['security']})...")
    cmd = ["networksetup", "-setairportnetwork", st.iface, ssid]
    if not net["open"]:
        try:
            pw = getpass.getpass("  Contraseña (vacío si es portal abierto): ")
        except Exception:
            pw = ""
        if pw:
            cmd.append(pw)
    out = sh(cmd, timeout=30)
    if out:
        print(f"  {C.Y}{out}{C.END}")
    time.sleep(2)
    ip = sh(["ipconfig", "getifaddr", st.iface])
    now = _ssid(st.iface)
    if now == ssid and ip:
        print(f"  {C.G}✅ Conectado a {ssid}  (IP {ip}).{C.END}")
        print(f"  {C.DIM}Siguiente paso sugerido: 'Auditar captive portal'.{C.END}")
    elif ip:
        print(f"  {C.CY}IP {ip}; red actual: {now}.{C.END}")
    else:
        print(f"  {C.R}No se pudo confirmar la conexión.{C.END} "
              f"¿Contraseña correcta / red al alcance?")


# ===========================================================================
# SONDA ACTIVA — golpea el portal y captura (no espera, actúa)
# ===========================================================================
def active_portal_probe(st):
    portal = st.net.get("portal")
    if not portal:
        s, u, b, h = http_probe(APPLE_PROBE)
        if s and b.strip() != APPLE_OK:
            portal = u if u != APPLE_PROBE else h.get("Location", u)
            st.net["portal"] = portal
    if not portal:
        gw = st.net.get("gateway")
        if gw:
            portal = f"http://{gw}/"
            print(f"  {C.DIM}Sin captive portal activo; sondeo el gateway {gw}.{C.END}")
    if not portal:
        print(f"  {C.Y}No hay objetivo HTTP. Conéctate a la red del reto primero.{C.END}")
        return

    print(f"  Sondeando {C.G}{portal}{C.END} y siguiendo redirecciones...\n")
    url, seen = portal, set()
    for _ in range(6):
        if url in seen:
            break
        seen.add(url)
        s, u, b, hdr = http_probe(url)
        print(f"    {C.CY}{s}{C.END}  {u}")
        for k, v in (hdr or {}).items():
            kl = k.lower()
            if kl == "set-cookie":
                st.captures.append({"kind": "setcookie", "value": f"Set-Cookie: {v}", "raw": v})
                print(f"      {C.M}Set-Cookie: {v[:110]}{C.END}")
                for kv in re.findall(r"([A-Za-z0-9_\-]+)=([A-Za-z0-9+/=._-]+)", v):
                    for dec in _try_decode(kv[1]):
                        print(f"        {C.CY}↳ {kv[0]} → {dec[:120]}{C.END}")
                        _hunt_timestamp(st, dec, kv[0])
            elif kl in ("date", "last-modified", "expires"):
                st.captures.append({"kind": "date", "value": f"{k}: {v}", "raw": v})
                print(f"      {C.CY}{k}: {v}{C.END}")
        _analyze_form(st, u, b)
        loc = (hdr or {}).get("Location")
        if loc and loc != url:
            url = loc
            continue
        break

    print(f"\n  {C.BOLD}Probando métodos de salida / bypass:{C.END}")
    _preauth_leak(st, True)
    _dns_egress(st, True)


def collect_flags(st):
    """Devuelve [(kind, texto)] con flags/fechas/epochs únicos de lo capturado."""
    out, seen = [], set()

    def add(kind, text):
        if text not in seen:
            seen.add(text)
            out.append((kind, text))

    for c in st.captures:
        txt = f"{c.get('raw','')} {c.get('value','')}"
        for tok in set(re.findall(r"[A-Za-z0-9+/=._-]{12,}", txt)):
            for dec in _try_decode(tok):
                if "flag" in dec.lower():
                    add("flag", dec[:200])
                for ep in re.findall(r"\b(1[0-9]{9})\b", dec):
                    when = dt.datetime.fromtimestamp(int(ep))
                    add("date", f"epoch {ep} = {when:%Y-%m-%d %H:%M:%S}")
        for iso in set(re.findall(r"20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", txt)):
            add("date", iso)
        m = re.search(r"(flag\{[^}]*\}|FLAG\{[^}]*\})", txt)
        if m:
            add("flag", m.group(1))
    return out


def hunt_flags(st):
    """Recorre TODO lo capturado buscando fechas, epochs y 'flag'."""
    print(f"  {C.BOLD}Rastreando flags, fechas y tokens en todo lo capturado...{C.END}\n")
    flags = collect_flags(st)
    for kind, text in flags:
        icon, col = ("🚩", C.R + C.BOLD) if kind == "flag" else ("⏱", C.Y)
        print(f"    {col}{icon} {text}{C.END}")
    if not flags:
        print(f"    {C.DIM}Nada todavía. Necesitas capturar tráfico/cookies del portal "
              f"real (usa Modo Misión conectado a la red del reto).{C.END}")
    else:
        print(f"\n  {C.G}{len(flags)} pista(s) temporal(es)/flag encontrada(s).{C.END}")


# ===========================================================================
# MODO MISIÓN — flujo guiado por estaciones (sube de nivel)
# ===========================================================================
def _stage(n, total, title):
    bar = "█" * n + "░" * (total - n)
    print(f"\n{C.M}{'═' * 62}{C.END}")
    print(f"  {C.BOLD}{C.CY}ESTACIÓN {n}/{total}{C.END}{C.BOLD} — {title}{C.END}")
    print(f"  {C.G}[{bar}]{C.END}")
    print(f"{C.M}{'═' * 62}{C.END}\n")


def _pause(msg="Enter para avanzar a la siguiente estación..."):
    try:
        input(f"\n{C.DIM}  ▶ {msg}{C.END}")
    except EOFError:
        pass


def m_mission(st):
    total = 6
    print(f"{C.BOLD}{C.CY}🎯  MODO MISIÓN{C.END} — te guío estación por estación "
          f"hasta la flag.\n{C.DIM}  En cada parada la herramienta prueba sola las "
          f"técnicas y te dice qué encontró.{C.END}")
    _pause("Enter para comenzar la misión...")

    _stage(1, total, "Reconocimiento: elegir y acceder a la red")
    if st.net.get("ip") and st.net.get("ssid", "").strip():
        print(f"  Conectado actualmente a {C.G}{st.net['ssid']}{C.END}.")
    try:
        if input("  ¿Escanear redes y elegir objetivo ahora? [s/N] ").strip().lower() == "s":
            m_scan(st)
    except EOFError:
        pass
    _pause()

    _stage(2, total, "Mapa de la red (IP, gateway, DNS, subred)")
    m_detect(st)
    _pause()

    _stage(3, total, "El portal: detección y pruebas de bypass")
    m_portal(st)
    _pause()

    _stage(4, total, "Interceptación activa: sondear el portal y capturar")
    active_portal_probe(st)
    _pause()

    _stage(5, total, "Caza de la flag: cookies, JWT y fechas")
    m_cookies(st)
    print()
    hunt_flags(st)
    _pause("Enter para generar el informe final...")

    _stage(6, total, "Informe final")
    m_report(st)

    print(f"\n{C.M}{'═' * 62}{C.END}")
    print(f"  {C.BOLD}{C.G}MISIÓN COMPLETADA{C.END}  ·  "
          f"{len(st.findings)} hallazgos · {len(st.captures)} capturas · "
          f"{len(st.hosts)} hosts")
    print(f"{C.M}{'═' * 62}{C.END}")


# ===========================================================================
# MÓDULO 🧰 — Caja de herramientas adaptativas (plan B cuando algo falla)
# ===========================================================================
def t_portal_multi(st):
    captive, portal, ev = detect_portal_multi()
    for name, res in ev:
        print(f"  {name:<10} {res}")
    if captive:
        st.net["portal"] = portal
        print(f"\n  {C.Y}Portal detectado{C.END} → {portal}")
    else:
        print(f"\n  {C.G}Ninguna sonda fue interceptada: salida libre / ya autenticado.{C.END}")


def t_web_ports(st):
    host = input(f"  Host [{st.net.get('gateway','')}]: ").strip() or st.net.get("gateway", "")
    if not host:
        print("  Sin host."); return
    ports = [80, 443, 8080, 8000, 8443, 3000, 5000, 8888, 81, 8081]
    print(f"\n  Probando puertos web en {C.G}{host}{C.END} (si uno cierra, prueba el siguiente):")
    openp = []
    for p in ports:
        try:
            socket.create_connection((host, p), timeout=1.5).close()
            openp.append(p)
            print(f"    {C.G}● ABIERTO {p}{C.END}")
        except Exception:
            print(f"    {C.DIM}○ cerrado {p}{C.END}")
    for p in openp:
        scheme = "https" if p in (443, 8443) else "http"
        s, u, b, h = http_probe(f"{scheme}://{host}:{p}/")
        tm = re.search(r"<title>(.*?)</title>", b or "", re.I | re.S)
        extra = f" · {tm.group(1).strip()[:48]}" if tm else ""
        print(f"    {C.CY}{scheme}://{host}:{p}/ → {s}{extra}{C.END}")
    if not openp:
        print(f"  {C.Y}Ningún puerto web abierto aquí; prueba otro host.{C.END}")


def t_arp(st):
    print("  Vecinos en la caché ARP (sin sudo, sin escanear):")
    out = sh(["arp", "-a", "-i", st.iface])
    rows = re.findall(r"\(([\d.]+)\) at ([0-9a-f:]{1,17})", out)
    for ip, mac in rows:
        gw = f"  {C.Y}← gateway{C.END}" if ip == st.net.get("gateway") else ""
        print(f"    {ip:<16} {mac}{gw}")
    if not rows:
        print(f"  {C.DIM}Vacío. Genera tráfico (pingea la subred) o usa nmap.{C.END}")


def t_egress(st):
    print("  Matriz de salida (¿qué puerto deja salir el firewall del portal?):")
    tests = [("DNS/53", "8.8.8.8", 53), ("HTTP/80", "1.1.1.1", 80),
             ("HTTPS/443", "1.1.1.1", 443), ("NTP/123", "129.6.15.28", 123),
             ("SSH/22", "1.1.1.1", 22)]
    openc = []
    for name, host, port in tests:
        try:
            socket.create_connection((host, port), timeout=3).close()
            openc.append(name)
            print(f"    {C.G}✓ {name} abierto → canal de bypass candidato{C.END}")
        except Exception:
            print(f"    {C.DIM}✗ {name} bloqueado{C.END}")
    if openc:
        st.add("HIGH", "Egress permitido antes de autenticar",
               f"Puertos de salida abiertos sin login: {', '.join(openc)}.",
               "Bloquear todo el egress de clientes no autenticados.")


