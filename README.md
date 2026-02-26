## 🇬🇧 English

# LukitaPort

Port scanner with a real-time web interface. FastAPI backend streams results as each port is checked — no waiting for the full scan to finish.

> **Warning:** For educational use only. Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal.

---

## What it does

LukitaPort opens TCP connections against each port of the target and classifies the result:

- **Open** — connection succeeded. Something is listening on that port.
- **Closed** — connection refused. The port is reachable but no service is running.
- **Filtered** — timed out. A firewall is probably dropping the packets.

Results stream to the browser live via **Server-Sent Events (SSE)** — the backend yields one JSON event per port as it scans, the frontend renders them in the table as they arrive.

---

## Scan modes

| Mode | Ports | When to use |
|---|---|---|
| Quick | 30 common ports | Fast check of typical services |
| Custom | User-defined range | When you know what range you care about |
| Full | 1 - 65535 | Full audit (can take several minutes) |

---

## Risk labels

Open ports are tagged by potential risk:

- **High** - protocols with a history of critical issues: FTP, Telnet, SMTP, NetBIOS, SMB, exposed databases (MySQL, PostgreSQL, Redis, MongoDB...), RDP, VNC.
- **Medium** - worth keeping an eye on: SSH, DNS, IMAP, alternative HTTP proxies.
- **Low** - standard web services: HTTP, HTTPS, SMTPS, IMAPS.

---

## Project structure

```
LukitaPort/
├── main.py                  # FastAPI server — /api/scan and /api/resolve
├── scanner.py               # scanning logic with native sockets
├── resolver.py              # DNS resolution and IP validation
├── requirements.txt
├── LICENSE
├── README.md
├── lukitaport-github.html   # standalone frontend for static hosting
└── frontend/
    ├── index.html           # web interface served by FastAPI
    └── styles.css
```

`lukitaport-github.html` is a self-contained version of the frontend (styles and scripts embedded) for static hosting like GitHub Pages. It tries to connect to `http://localhost:8000`; if unavailable, it falls back to a simulation mode.

---

## Installation

Requires Python 3.10+

```bash
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scriptsctivate         # Windows

pip install -r requirements.txt
```

---

## Usage

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`, enter a target IP or domain, pick a mode and hit **Iniciar Escaneo**. Results appear as the scan runs. Export to JSON, CSV or HTML report when done.

---

## Technical notes

- The scan is single-threaded and sequential by design — easier to follow, enough for learning. A production version would parallelize with `asyncio` or a thread pool.
- Full mode (1-65535) can take anywhere from 1 to 20 minutes depending on timeout and network conditions.
- `python-nmap` is in the dependencies in case you want to extend it with version detection, but the base scan does not use it.

---

## License

MIT. See the LICENSE file.

---

**Author:** jaimefg1888

---
---

## 🇪🇸 Español

# LukitaPort

Escáner de puertos con interfaz web en tiempo real. El backend en FastAPI va enviando los resultados puerto a puerto según los escanea, sin esperar a que termine todo.

> **Aviso:** Solo para uso educativo. Escanea únicamente sistemas propios o sobre los que tengas autorización escrita. El escaneo no autorizado puede ser ilegal.

---

## Qué hace

LukitaPort abre conexiones TCP contra cada puerto del objetivo y clasifica el resultado:

- **Abierto** — la conexión se estableció. Hay algo escuchando.
- **Cerrado** — la conexión fue rechazada. El puerto responde pero no hay servicio activo.
- **Filtrado** — timeout. Probablemente un firewall está descartando los paquetes.

Los resultados llegan al navegador en tiempo real mediante **Server-Sent Events (SSE)** — el backend hace yield de un evento JSON por puerto mientras escanea, y el frontend los va pintando en la tabla según llegan.

---

## Modos de escaneo

| Modo | Puertos | Cuándo usarlo |
|---|---|---|
| Rápido | 30 puertos comunes | Revisión rápida de servicios habituales |
| Personalizado | Rango definido | Cuando sabes qué rango te interesa |
| Completo | 1 - 65535 | Auditoría exhaustiva (puede tardar varios minutos) |

---

## Niveles de riesgo

Los puertos abiertos se etiquetan según su riesgo potencial:

- **Alto** — protocolos con historial de vulnerabilidades críticas: FTP, Telnet, SMTP, NetBIOS, SMB, bases de datos expuestas (MySQL, PostgreSQL, Redis, MongoDB...), RDP, VNC.
- **Medio** — servicios que conviene vigilar: SSH, DNS, IMAP, proxies alternativos.
- **Bajo** — servicios web estándar: HTTP, HTTPS, SMTPS, IMAPS.

---

## Estructura del proyecto

```
LukitaPort/
├── main.py                  # servidor FastAPI — /api/scan y /api/resolve
├── scanner.py               # lógica de escaneo con sockets nativos
├── resolver.py              # resolución DNS y validación de IP
├── requirements.txt
├── LICENSE
├── README.md
├── lukitaport-github.html   # frontend standalone para hosting estático
└── frontend/
    ├── index.html           # interfaz web servida por FastAPI
    └── styles.css
```

`lukitaport-github.html` es una versión autocontenida del frontend (estilos y scripts embebidos) pensada para hosting estático como GitHub Pages. Intenta conectar a `http://localhost:8000`; si no está disponible, cae a un modo simulación.

---

## Instalación

Requiere Python 3.10+

```bash
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scriptsctivate         # Windows

pip install -r requirements.txt
```

---

## Uso

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Abre `http://localhost:8000`, escribe la IP o dominio objetivo, elige el modo y pulsa **Iniciar Escaneo**. Los resultados aparecen mientras el escaneo avanza. Al terminar puedes exportar en JSON, CSV o informe HTML.

---

## Notas técnicas

- El escaneo es secuencial y monohilo a propósito — más fácil de seguir y suficiente para aprender. Una versión en producción lo paralelizaría con `asyncio` o un thread pool.
- El modo completo (1-65535) puede tardar entre 1 y 20 minutos según el timeout y la red.
- `python-nmap` está en las dependencias por si quieres ampliar con detección de versiones, pero el escaneo base no lo usa.

---

## Licencia

MIT. Consulta el archivo LICENSE.

---

**Autor:** jaimefg1888
