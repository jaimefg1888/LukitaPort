# LukitaPort

Port scanner with a real-time web interface. Python backend (FastAPI + raw sockets) streams results to the browser as each port is checked, no page refresh needed.

> ⚠️ **For educational use only.** Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

---

## Español

### ¿Qué hace exactamente?

LukitaPort abre conexiones TCP contra cada puerto del objetivo y, dependiendo de lo que ocurra, clasifica el resultado como:

- **Abierto** — la conexión se estableció (`connect_ex` devolvió 0). Hay algo escuchando.
- **Cerrado** — la conexión fue rechazada. El puerto existe pero no hay servicio activo.
- **Filtrado** — la conexión expiró (timeout). Lo más probable es que un firewall esté descartando los paquetes.

Cada resultado llega al navegador en tiempo real mediante **Server-Sent Events (SSE)**: el backend hace streaming de eventos JSON uno a uno mientras escanea, y el frontend los pinta en la tabla según llegan, sin esperar a que termine el escaneo completo.

### Cómo funciona por dentro

```
Usuario introduce IP/dominio
        ↓
Frontend limpia la entrada (quita https://, paths, etc.)
        ↓
GET /api/scan?target=...&mode=...&timeout=...
        ↓
Backend resuelve DNS si es un dominio → obtiene la IP
        ↓
Construye la lista de puertos según el modo elegido
        ↓
Escanea puerto a puerto con sockets nativos
        ↓
Hace yield de cada resultado como evento SSE → data: {...}\n\n
        ↓
Frontend recibe cada evento y actualiza la tabla en vivo
        ↓
Evento "done" → muestra resumen final + guarda en historial
```

### Modos de escaneo

| Modo | Puertos | Cuándo usarlo |
|---|---|---|
| Rápido | 30 puertos comunes | Revisión rápida de servicios habituales |
| Personalizado | Rango definido por el usuario | Cuando sabes qué rango te interesa |
| Completo | 1 – 65535 | Auditoría exhaustiva (puede tardar varios minutos) |

### Clasificación de riesgo

Los puertos abiertos se etiquetan según su riesgo potencial:

- **Alto** — protocolos con historial de vulnerabilidades críticas: FTP (21), Telnet (23), SMTP (25), NetBIOS (139), SMB (445), bases de datos expuestas (MySQL, PostgreSQL, Redis, MongoDB…), RDP (3389), VNC (5900).
- **Medio** — servicios que conviene monitorizar: SSH (22), DNS (53), IMAP (143), proxies alternativos.
- **Bajo** — servicios web estándar: HTTP (80), HTTPS (443), SMTPS, IMAPS.

### Estructura del proyecto

```
LukitaPort/
├── main.py              # Servidor FastAPI — endpoints /api/scan y /api/resolve
├── scanner.py           # Lógica de escaneo con sockets nativos
├── resolver.py          # Resolución DNS y validación de IP
├── requirements.txt
├── LICENSE
├── README.md
└── frontend/
    ├── index.html       # Interfaz web (servida por FastAPI en localhost)
    └── styles.css       # Estilos
```

También existe **`lukitaport-github.html`** en la raíz: una versión standalone del frontend con todos los estilos y scripts embebidos, pensada para servirse como página estática (GitHub Pages, etc.). Intenta conectar al backend en `http://localhost:8000`; si no está disponible, cae a un modo simulación para que la interfaz siga siendo navegable.

### Instalación

Requisitos: Python 3.10+

```bash
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

### Uso

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Abre `http://localhost:8000` en el navegador.

1. Escribe la IP o dominio objetivo (admite `https://ejemplo.com` — lo limpia automáticamente).
2. Elige el modo de escaneo.
3. Ajusta el timeout si la red es lenta o el objetivo tiene latencia alta.
4. Pulsa **Iniciar Escaneo**.

Los resultados aparecen en la tabla mientras el escaneo avanza. Al terminar puedes exportarlos en JSON, CSV o como informe HTML.

### Notas técnicas

- El escaneo es **single-threaded y secuencial** a propósito: más sencillo de entender y suficiente para aprender. En producción se paralelizaría con `asyncio` o un thread pool.
- El modo completo (1-65535) puede tardar entre 1 y 20 minutos dependiendo del timeout y la red.
- En redes locales los resultados son prácticamente instantáneos; en hosts remotos influye mucho la latencia.
- `python-nmap` está en las dependencias por si quieres ampliar con detección de versiones, pero el escaneo base no lo usa.

### Advertencia legal

Escanear puertos de sistemas que no te pertenecen o para los que no tienes autorización escrita puede constituir un delito informático. Úsalo solo en tu propia infraestructura o en entornos de laboratorio.

---

## English

### What does it do?

LukitaPort opens TCP connections against each port of the target and classifies the result as:

- **Open** — connection succeeded (`connect_ex` returned 0). Something is listening.
- **Closed** — connection refused. The port is reachable but no service is running on it.
- **Filtered** — connection timed out. Most likely a firewall is dropping the packets.

Results reach the browser in real time via **Server-Sent Events (SSE)**: the backend streams JSON events one by one as it scans, and the frontend renders them in the table as they arrive, without waiting for the full scan to finish.

### How it works internally

```
User enters IP/domain
        ↓
Frontend sanitizes input (strips https://, paths, etc.)
        ↓
GET /api/scan?target=...&mode=...&timeout=...
        ↓
Backend resolves DNS if it's a domain → gets the IP
        ↓
Builds port list based on selected mode
        ↓
Scans port by port using native sockets
        ↓
Yields each result as an SSE event → data: {...}\n\n
        ↓
Frontend receives each event and updates the table live
        ↓
"done" event → shows final summary + saves to session history
```

### Scan modes

| Mode | Ports | When to use |
|---|---|---|
| Quick | 30 common ports | Fast check of typical services |
| Custom | User-defined range | When you know what range you care about |
| Full | 1 – 65535 | Full audit (can take several minutes) |

### Risk classification

Open ports are labeled by potential risk:

- **High** — protocols with a history of critical vulnerabilities: FTP (21), Telnet (23), SMTP (25), NetBIOS (139), SMB (445), exposed databases (MySQL, PostgreSQL, Redis, MongoDB…), RDP (3389), VNC (5900).
- **Medium** — services worth monitoring: SSH (22), DNS (53), IMAP (143), alternative proxies.
- **Low** — standard web services: HTTP (80), HTTPS (443), SMTPS, IMAPS.

### Project structure

```
LukitaPort/
├── main.py              # FastAPI server — /api/scan and /api/resolve endpoints
├── scanner.py           # Scanning logic with native sockets
├── resolver.py          # DNS resolution and IP validation
├── requirements.txt
├── LICENSE
├── README.md
└── frontend/
    ├── index.html       # Web interface (served by FastAPI on localhost)
    └── styles.css       # Styles
```

There's also **`lukitaport-github.html`** in the root: a standalone version of the frontend with all styles and scripts embedded, meant to be served as a static page (GitHub Pages, etc.). It tries to connect to the backend at `http://localhost:8000`; if unavailable, it falls back to a simulation mode so the interface stays usable.

### Installation

Requirements: Python 3.10+

```bash
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

### Usage

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser.

1. Enter a target IP or domain (it accepts `https://example.com` — it strips it automatically).
2. Choose a scan mode.
3. Adjust the timeout if the network is slow or the target has high latency.
4. Hit **Iniciar Escaneo**.

Results appear in the table as the scan progresses. When done, you can export them as JSON, CSV, or an HTML report.

### Technical notes

- The scan is **single-threaded and sequential** by design — easier to follow and enough for learning purposes. A production version would parallelize with `asyncio` or a thread pool.
- Full mode (1-65535) can take anywhere from 1 to 20 minutes depending on timeout and network conditions.
- On local networks results are nearly instant; on remote hosts, latency makes a big difference.
- `python-nmap` is in the dependencies in case you want to extend it with version detection, but the base scan doesn't use it.

### Legal warning

Scanning ports on systems you don't own or haven't received explicit written authorization to test may constitute a computer crime. Use this only on your own infrastructure or lab environments.

---

## GitHub description

**EN:** Port scanner with real-time web UI. Python sockets + FastAPI SSE backend, vanilla JS frontend. For educational use.

**ES:** Escáner de puertos con interfaz web en tiempo real. Backend en Python (sockets + FastAPI SSE) y frontend en JS vanilla. Uso educativo.

---

*jaimefg1888 — python + fastapi + vanilla js*
