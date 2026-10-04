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
