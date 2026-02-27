## 🇬🇧 English

# LukitaPort v2.0

Advanced port scanner with a real-time web interface. The FastAPI backend streams results as each port is scanned — no waiting for the full scan to finish. Includes fingerprinting, advanced security audit, CVE lookup, network discovery, subdomain enumeration, anonymous mode, and multi-format export.

> **Warning:** For educational use only. Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

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
| Full | 1–65535 | Full audit (can take several minutes) |

---

## Intensity profiles

| Profile | Concurrency | Delay | Notes |
|---|---|---|---|
| Normal | 100 simultaneous | None | Balanced, default |
| Stealth | 10 simultaneous | 0.5s per port | IDS/firewall evasion |
| Aggressive | 1000 simultaneous | None | Maximum speed |

---

## Anonymous mode

Enabling **Anonymous Mode** automatically forces the **Stealth** profile, adds random inter-port delays, and minimizes the scan's fingerprint to reduce the chance of detection on monitored networks. Toggle it in the scan configuration panel before starting the scan.

---

## Risk labels

Open ports are tagged by potential risk:

- **High** — protocols with a history of critical vulnerabilities: FTP (21), Telnet (23), SMTP (25), POP3 (110), NetBIOS (139), SMB (445), MSSQL (1433), Oracle (1521), MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900), Redis (6379), MongoDB (27017), PPTP (1723).
- **Medium** — worth monitoring: SSH (22), DNS (53), RPC (111), MSRPC (135), IMAP (143), HTTP-Alt (8080/8888), Elasticsearch (9200).
- **Low** — standard web services: HTTP (80), HTTPS (443), SMTPS (465), SMTP/TLS (587), IMAPS (993), POP3S (995), HTTPS-Alt (8443).

---

## Fingerprinting

Click **Fingerprinting** after the scan completes to run nmap's service version detection (`-sV`) against all open ports. This enriches the **Version / Banner** column with product names and version numbers (e.g. `Pure-FTPd`, `nginx`, `Dovecot imapd`), which are then used by the CVE lookup for more precise results.

> nmap must be installed on the system: `sudo apt install nmap` (Linux) or `winget install Insecure.Nmap` (Windows).

---

## Advanced audit

After the scan, if any web port (80, 443, 8080, 8443) is found open, the **Advanced Audit** panel appears automatically with five tabs:

### 🔒 HTTP Headers
Audits the target's security headers. Each missing header is graded by severity (High / Medium / Low) and includes a ready-to-copy nginx directive so you can fix it immediately. A final score (0–100) and letter grade (A–F) summarises the overall posture.

### 🔬 Technologies
Detects web technologies via Playwright browser automation: CMS, frameworks, web servers, CDNs, analytics, e-commerce platforms. Results are grouped by category.

### 🗂 Sensitive Paths
Crawls a list of known sensitive paths (admin panels, backup files, config files, etc.) and reports which ones return 200 OK (publicly accessible) vs 403 Forbidden (exist but blocked), with severity tags.

### 🔐 SSL/TLS
For open HTTPS ports (443, 8443), analyzes the certificate and cipher configuration:
- Certificate validity, expiry date, days remaining
- Subject / Issuer / SANs
- Cipher name, protocol version, key bits
- Detects: expired certs, expiring soon (<30 days), self-signed certs, weak ciphers (RC4, DES, NULL…), deprecated protocols (SSLv2/3, TLS 1.0/1.1)
- Letter grade: A / B / C / F

### 🐛 CVE
Queries the NVD (National Vulnerability Database) for known CVEs affecting the detected services. Run Fingerprinting first for precise version-aware results; or click **Search CVEs now** to run it against service names only. Results are sorted by CVSS score and show severity, description, and a direct NVD link.

> The NVD free API allows 1 request every 6 seconds. For 13 open ports, expect ~85 seconds. Results are cached for 10 minutes.

---

## OSINT & Network Discovery

Below the scan configuration panel:

### Ping Sweep (CIDR)
Enter a CIDR range (e.g. `192.168.1.0/24`) to discover live hosts on the network. Click any result to load it as a scan target.

### Subdomain Enumeration
Enter a domain to enumerate its subdomains via the crt.sh certificate transparency logs. Results show the subdomain, resolved IP (if any), certificate expiry date, and a one-click scan button.

---

## GeoIP enrichment

During the scan, the target IP is automatically enriched with geolocation and ASN data (country, city, ISP, AS number) displayed in the status bar.

---

## Export formats

| Format | Generated by | Contents |
|---|---|---|
| JSON | Client | Full scan data + metadata + GeoIP + versions |
| CSV | Client | Port, state, service, risk, response time, version |
| HTML | Client | Self-contained visual report |
| PDF | Server (ReportLab) | Formatted report with audit data and optional screenshot |
| Markdown | Server | Report in .md format for documentation |

---

## Project structure

```
LukitaPort/
├── main.py              # FastAPI server — all API endpoints
├── scanner.py           # Async port scanning, banner grabbing, nmap fingerprinting
├── resolver.py          # DNS resolution and IP validation
├── auditor.py           # HTTP headers, WAF, technologies, sensitive paths
├── ssl_analyzer.py      # SSL/TLS certificate and cipher analysis
├── cve_lookup.py        # NVD CVE lookup with async HTTP and TTL cache
├── pdf_generator.py     # PDF report generation (ReportLab)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── LICENSE
├── README.md
└── frontend/
    ├── index.html       # Main interface
    ├── styles.css       # Dark theme styles
    ├── main.js          # Entry point — event listeners
    ├── api.js           # SSE scan, fingerprint, audit, CVE, discover, subdomains
    ├── ui.js            # DOM helpers, table rendering, audit rendering, toasts
    ├── state.js         # Single source of truth — shared app state
    └── export.js        # JSON, CSV, HTML, PDF, Markdown export
```

---

## Installation

Requires Python 3.10+ and nmap.

```bash
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

pip install -r requirements.txt
playwright install chromium --with-deps
```

---

## Usage

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`, enter a target IP or domain, choose a mode and profile, and hit **Start Scan**. Results appear as the scan runs.

---

## Docker

```bash
docker compose up --build      # first run
docker compose up              # subsequent runs
docker compose up -d           # detached
```

Open `http://localhost:8000`. nmap and Playwright/Chromium are included in the image.

---

## Technical notes

- The async scan uses `asyncio` with a semaphore — concurrency is controlled by the selected profile (10 / 100 / 1000 simultaneous connections).
- Full mode (1–65535) can take anywhere from 1 to 20 minutes depending on timeout and network conditions.
- CVE results are cached in memory for 10 minutes to avoid hammering the NVD rate limit.
- Screenshots are captured by Playwright in the background and do not block the scan or the audit.

---

## License

MIT. See the LICENSE file.

---

**Author:** jaimefg1888

---
---

## 🇪🇸 Español

# LukitaPort v2.0

Escáner de puertos con interfaz web en tiempo real. El backend en FastAPI va enviando los resultados puerto a puerto según los escanea, sin esperar a que termine todo. Incluye fingerprinting, auditoría de seguridad avanzada, búsqueda de CVEs, descubrimiento de red, enumeración de subdominios, modo anónimo y exportación en múltiples formatos.

> **Aviso:** Solo para uso educativo. Escanea únicamente sistemas propios o sobre los que tengas autorización escrita. El escaneo no autorizado puede ser ilegal en tu jurisdicción.

---

## Qué hace

LukitaPort abre conexiones TCP contra cada puerto del objetivo y clasifica el resultado:

- **Abierto** — la conexión se estableció. Hay algo escuchando en ese puerto.
- **Cerrado** — la conexión fue rechazada. El puerto responde pero no hay servicio activo.
- **Filtrado** — timeout. Probablemente un firewall está descartando los paquetes.

Los resultados llegan al navegador en tiempo real mediante **Server-Sent Events (SSE)** — el backend hace yield de un evento JSON por puerto mientras escanea, y el frontend los va pintando en la tabla según llegan.

---

## Modos de escaneo

| Modo | Puertos | Cuándo usarlo |
|---|---|---|
| Rápido | 30 puertos comunes | Revisión rápida de servicios habituales |
| Personalizado | Rango definido | Cuando sabes qué rango te interesa |
| Completo | 1–65535 | Auditoría exhaustiva (puede tardar varios minutos) |

---

## Perfiles de intensidad

| Perfil | Concurrencia | Delay | Notas |
|---|---|---|---|
| Normal | 100 simultáneas | Ninguno | Equilibrado, por defecto |
| Stealth | 10 simultáneas | 0,5s por puerto | Evasión de IDS/firewall |
| Agresivo | 1000 simultáneas | Ninguno | Máxima velocidad |

---

## Modo anónimo

Al activar el **Modo Anónimo** se fuerza automáticamente el perfil **Stealth**, se añaden delays aleatorios entre puertos y se minimiza la huella del escaneo para reducir la probabilidad de detección en redes monitorizadas. Actívalo en el panel de configuración antes de iniciar el escaneo.

---

## Niveles de riesgo

Los puertos abiertos se etiquetan según su riesgo potencial:

- **Alto** — protocolos con historial de vulnerabilidades críticas: FTP (21), Telnet (23), SMTP (25), POP3 (110), NetBIOS (139), SMB (445), MSSQL (1433), Oracle (1521), MySQL (3306), RDP (3389), PostgreSQL (5432), VNC (5900), Redis (6379), MongoDB (27017), PPTP (1723).
- **Medio** — servicios que conviene vigilar: SSH (22), DNS (53), RPC (111), MSRPC (135), IMAP (143), HTTP-Alt (8080/8888), Elasticsearch (9200).
- **Bajo** — servicios web estándar: HTTP (80), HTTPS (443), SMTPS (465), SMTP/TLS (587), IMAPS (993), POP3S (995), HTTPS-Alt (8443).

---

## Fingerprinting

Haz clic en **Fingerprinting** tras completar el escaneo para ejecutar la detección de versiones de nmap (`-sV`) sobre todos los puertos abiertos. Esto enriquece la columna **Versión / Banner** con nombres de producto y número de versión (p. ej. `Pure-FTPd`, `nginx`, `Dovecot imapd`), que luego usa la búsqueda de CVEs para obtener resultados más precisos.

> nmap debe estar instalado en el sistema: `sudo apt install nmap` (Linux) o `winget install Insecure.Nmap` (Windows).

---

## Auditoría avanzada

Tras el escaneo, si se detecta algún puerto web abierto (80, 443, 8080, 8443), el panel de **Auditoría Avanzada** aparece automáticamente con cinco pestañas:

### 🔒 Cabeceras HTTP
Audita las cabeceras de seguridad del objetivo. Cada cabecera ausente se clasifica por severidad (Alto / Medio / Bajo) e incluye una directiva nginx lista para copiar y aplicar. Una puntuación final (0–100) y letra (A–F) resume el estado global.

### 🔬 Tecnologías
Detecta tecnologías web mediante automatización del navegador con Playwright: CMS, frameworks, servidores web, CDNs, analítica, plataformas de e-commerce. Los resultados se agrupan por categoría.

### 🗂 Rutas sensibles
Comprueba una lista de rutas conocidas (paneles de administración, backups, archivos de configuración, etc.) e informa de cuáles devuelven 200 OK (accesibles públicamente) y cuáles 403 Forbidden (existen pero están bloqueadas), con etiquetas de severidad.

### 🔐 SSL/TLS
Para los puertos HTTPS abiertos (443, 8443), analiza el certificado y la configuración de cifrado:
- Validez del certificado, fecha de expiración, días restantes
- Sujeto / Emisor / SANs
- Nombre del cifrado, versión del protocolo, bits de la clave
- Detecta: certificados expirados, próximos a expirar (<30 días), autofirmados, cifrados débiles (RC4, DES, NULL…), protocolos deprecados (SSLv2/3, TLS 1.0/1.1)
- Nota final: A / B / C / F

### 🐛 CVE
Consulta el NVD (National Vulnerability Database) en busca de CVEs conocidos que afecten a los servicios detectados. Ejecuta Fingerprinting primero para obtener resultados precisos basados en versión; o haz clic en **Buscar CVEs ahora** para lanzarlo directamente contra los nombres de servicio. Los resultados se ordenan por puntuación CVSS e incluyen severidad, descripción y enlace directo al NVD.

> La API gratuita del NVD permite 1 petición cada 6 segundos. Con 13 puertos abiertos, espera ~85 segundos. Los resultados se cachean durante 10 minutos.

---

## OSINT & Descubrimiento de red

Panel situado bajo la configuración del escaneo:

### Ping Sweep (CIDR)
Introduce un rango CIDR (p. ej. `192.168.1.0/24`) para descubrir hosts activos en la red. Haz clic en cualquier resultado para cargarlo como objetivo del escaneo.

### Enumeración de subdominios
Introduce un dominio para enumerar sus subdominios consultando los logs de transparencia de certificados de crt.sh. Los resultados muestran el subdominio, la IP resuelta (si la hay), la fecha de expiración del certificado y un botón para escanearlo directamente.

---

## Enriquecimiento GeoIP

Durante el escaneo, la IP del objetivo se enriquece automáticamente con datos de geolocalización y ASN (país, ciudad, ISP, número AS), que se muestran en la barra de estado.

---

## Formatos de exportación

| Formato | Generado por | Contenido |
|---|---|---|
| JSON | Cliente | Datos completos + metadatos + GeoIP + versiones |
| CSV | Cliente | Puerto, estado, servicio, riesgo, tiempo, versión |
| HTML | Cliente | Informe visual autocontenido |
| PDF | Servidor (ReportLab) | Informe formateado con datos de auditoría y screenshot opcional |
| Markdown | Servidor | Informe en formato .md para documentación |

---

## Estructura del proyecto

```
LukitaPort/
├── main.py              # Servidor FastAPI — todos los endpoints de la API
├── scanner.py           # Escaneo async, captura de banners, fingerprinting nmap
├── resolver.py          # Resolución DNS y validación de IP
├── auditor.py           # Cabeceras HTTP, WAF, tecnologías, rutas sensibles
├── ssl_analyzer.py      # Análisis de certificado SSL/TLS y cifrado
├── cve_lookup.py        # Búsqueda de CVEs en NVD con HTTP async y caché TTL
├── pdf_generator.py     # Generación de informes PDF (ReportLab)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── LICENSE
├── README.md
└── frontend/
    ├── index.html       # Interfaz principal
    ├── styles.css       # Estilos tema oscuro
    ├── main.js          # Punto de entrada — listeners de eventos
    ├── api.js           # SSE scan, fingerprint, auditoría, CVE, discover, subdominios
    ├── ui.js            # Helpers DOM, renderizado de tabla y auditoría, toasts
    ├── state.js         # Fuente única de verdad — estado compartido de la app
    └── export.js        # Exportación JSON, CSV, HTML, PDF, Markdown
```

---

## Instalación

Requiere Python 3.10+ y nmap.

```bash
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

pip install -r requirements.txt
playwright install chromium --with-deps
```

---

## Uso

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Abre `http://localhost:8000`, escribe la IP o dominio objetivo, elige el modo y perfil, y pulsa **Iniciar Escaneo**. Los resultados aparecen mientras el escaneo avanza.

---

## Docker

```bash
docker compose up --build      # primera vez
docker compose up              # ejecuciones posteriores
docker compose up -d           # modo desatendido
```

Abre `http://localhost:8000`. nmap y Playwright/Chromium están incluidos en la imagen.

---

## Notas técnicas

- El escaneo async usa `asyncio` con un semáforo — la concurrencia la controla el perfil seleccionado (10 / 100 / 1000 conexiones simultáneas).
- El modo completo (1–65535) puede tardar entre 1 y 20 minutos según el timeout y las condiciones de red.
- Los resultados de CVEs se cachean en memoria durante 10 minutos para no saturar el límite de peticiones del NVD.
- Los screenshots se capturan con Playwright en background y no bloquean ni el escaneo ni la auditoría.

---

## Licencia

MIT. Consulta el archivo LICENSE.

---

**Autor:** jaimefg1888
