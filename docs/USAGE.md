# Guía de uso — LonxsGuard

Esta guía explica paso a paso cómo usar cada módulo. Recuerda: **solo en redes
propias o autorizadas**.

## 1. Arrancar

```bash
python3 lonxsguard.py
```

Verás una intro animada y luego el menú principal. Navega con **↑ / ↓** y
**Enter**; sal con **q**. Las teclas **1–9** son atajos directos.

## 2. Flujo recomendado

1. **📶 Redes cercanas** — escanea el entorno y, si quieres, conéctate a una red.
2. **🌐 Detectar red** (en *Avanzado*) — confirma IP, gateway, DNS y subred.
3. **🚪 Auditar captive portal** — detecta el portal y prueba debilidades comunes.
4. **📡 Interceptar tráfico** — captura cabeceras y cookies (pide `sudo`).
5. **🍪 Analizar cookies / JWT** — decodifica tokens y busca fechas/flags.
6. **📄 Reporte HTML** — genera el dashboard con todo lo encontrado.

## 3. Módulos clave

### Reconocimiento Wi-Fi
Lista las redes cercanas con señal, canal y tipo de seguridad usando
`system_profiler`. No requiere conectarse. En macOS reciente puede pedir permiso
de **Localización** para la terminal.

### Auditoría de captive portal
Usa varias sondas (Apple, Android, Microsoft) para detectar el portal aunque
una quede permitida. Reporta: login servido sobre HTTP, fuga de conectividad
antes de autenticar y DNS externo resoluble (posible túnel DNS).

### Interceptación de cabeceras
Lanza `tcpdump` sobre la interfaz y extrae peticiones, `Cookie`, `Authorization`,
credenciales en formularios y cabeceras de fecha. Requiere `sudo`.

### Análisis de cookies / JWT
Toma lo capturado, decodifica base64 y JWT, y convierte `epoch` a fecha legible.
Útil para localizar marcas de tiempo dentro de tokens de sesión.

### Enumeración de hosts
Descubre equipos vivos y puertos abiertos con `nmap`. Como alternativa sin
privilegios, puede leer la **caché ARP** (`arp -a`) para listar vecinos.

### Pruebas de login web
Descubre páginas de login en la red, autodetecta los campos del formulario y
prueba contraseñas de un diccionario, en paralelo, deteniéndose al primer éxito.

### Caja de herramientas
- **Buscador de puertos web**: si un puerto está cerrado, prueba el siguiente.
- **Matriz de salida**: comprueba qué puertos deja salir el firewall.
- **Utilidades de MAC / DHCP**: ver/renovar según haga falta.

## 4. Reportes

Se guardan en `reports/` como HTML autocontenido (se puede abrir sin internet).
Esta carpeta está en `.gitignore` porque contiene datos de redes reales.

## 5. Diccionarios

Coloca cualquier `.txt` en `wordlists/` y aparecerá en los módulos que los usan.
Incluidos: `starter.txt` (comunes) y `espanol.txt` (en español).
