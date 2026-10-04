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


