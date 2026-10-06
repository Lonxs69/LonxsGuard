<h1 align="center">🛡️ LonxsGuard</h1>

<p align="center"><b>Herramienta creada por <a href="https://github.com/Lonxs69">Junior De León (@lonxs69)</a></b></p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-macOS-000000?logo=apple&logoColor=white">
  <img src="https://img.shields.io/badge/dependencies-none-2ea44f">
  <img src="https://img.shields.io/badge/license-MIT-blue">
  <img src="https://img.shields.io/github/stars/Lonxs69/LonxsGuard?style=flat&logo=github&color=yellow">
  <img src="https://img.shields.io/github/last-commit/Lonxs69/LonxsGuard">
</p>

<p align="center">
Toolkit de <b>auditoría de seguridad de redes</b> para macOS, en una sola terminal interactiva.<br>
Un comando, menú navegable, y un reporte HTML con estética de terminal. <b>Cero dependencias externas.</b>
</p>

---

## ✨ ¿Qué hace?

LonxsGuard reúne en una interfaz limpia las fases típicas de una auditoría de red,
pensado para redes **propias o con autorización explícita**:

| Módulo | Descripción |
|--------|-------------|
| 📶 **Reconocimiento Wi-Fi** | Escanea redes cercanas (SSID, señal, canal, seguridad) sin conectarse |
| 🚪 **Auditoría de captive portal** | Detección multi-sonda (Apple/Android/Microsoft), login sobre HTTP, fuga pre-auth, DNS abierto |
| 📡 **Interceptación de tráfico** | Captura cabeceras HTTP, cookies y credenciales con `tcpdump` |
| 🍪 **Análisis de cookies / JWT** | Decodifica tokens y extrae fechas y marcas de tiempo automáticamente |
| 🗺️ **Enumeración de hosts** | Descubre equipos y puertos abiertos con `nmap` (o caché ARP, sin privilegios) |
| 🔑 **Pruebas de login web** | Fuerza bruta de formularios con autodetección de campos (multihilo) |
| 📶 **Evaluación Wi-Fi** | Pruebas de clave con filtros inteligentes (longitud, patrón) |
| 🧰 **Caja de herramientas** | Buscador de puertos web, matriz de salida, utilidades de MAC/DHCP |
| 📄 **Reporte HTML** | Dashboard de una página, estética terminal hacker, ligero y fluido |

> Todo corre con la **librería estándar de Python** + herramientas nativas de macOS
> (`networksetup`, `system_profiler`, `tcpdump`, `dig`, `arp`) + `nmap` opcional.

---

## 🖥️ Requisitos

- **macOS** (probado en versiones recientes)
- **Python 3.9+** (viene con macOS)
- `nmap` opcional (para enumeración de puertos): `brew install nmap`

---

## 📦 Instalación

```bash
git clone https://github.com/Lonxs69/LonxsGuard.git
cd LonxsGuard
chmod +x lonxsguard.py
python3 lonxsguard.py
```

### Comando global (opcional)

Para lanzarlo desde cualquier lugar escribiendo `LonxsGuard`:

```bash
sudo ln -sf "$PWD/lonxsguard.py" /usr/local/bin/LonxsGuard
chmod +x /usr/local/bin/LonxsGuard
```

---

## 🚀 Uso

```bash
python3 lonxsguard.py
```

- Navega el menú con **↑ / ↓** (o `j` / `k`), **Enter** para entrar, **q** para salir.
- Teclas **1–9** como atajo directo a cada módulo.
- El estado (hallazgos, capturas, hosts) se acumula durante la sesión y se vuelca al reporte.

El módulo de interceptación pide `sudo`. Los reportes se guardan en `reports/`
y se abren en el navegador.

Para el reconocimiento Wi-Fi, macOS puede requerir activar **Localización**
para tu terminal: *Ajustes del Sistema → Privacidad y seguridad → Localización*.

### Diccionarios

Las listas de palabras viven en `wordlists/`. Incluye `starter.txt` y `espanol.txt`.
Puedes añadir las tuyas (cualquier `.txt` aparece automáticamente en el menú).

---

## 📄 El reporte

Cada sesión genera un **dashboard HTML** de una sola página con estética de terminal:
resumen por severidad, hallazgos priorizados, datos interceptados y hosts.
Ligero (sin librerías pesadas) y fluido en cualquier navegador.

---

## ⚠️ Aviso legal

LonxsGuard es una herramienta **educativa y de auditoría defensiva**.
Úsala **únicamente** sobre redes y sistemas de tu propiedad o para los que
tengas **autorización por escrito**. El acceso no autorizado a redes o
sistemas de terceros es **ilegal**. El autor no se hace responsable del mal uso.

---

## 📝 Licencia

[MIT](LICENSE) © 2026 **Junior De León** ([@lonxs69](https://github.com/Lonxs69))
