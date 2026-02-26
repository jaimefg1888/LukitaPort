# LukitaPort 🔍

**Escáner de puertos con interfaz web profesional. Backend en Python (FastAPI) y frontend en HTML/CSS/JS vanilla.**

> ⚠️ **AVISO LEGAL / LEGAL NOTICE:** Esta herramienta es exclusivamente para uso educativo y en sistemas sobre los que posees autorización expresa. El escaneo no autorizado de redes ajenas puede ser ilegal. / *This tool is strictly for educational use and systems you own or have explicit authorization to scan. Unauthorized port scanning may be illegal.*

---

## Español

### ¿Qué es LukitaPort?

LukitaPort es una herramienta de escaneo de puertos con interfaz web, diseñada para aprender y practicar conceptos de redes y seguridad en entornos controlados. Los resultados llegan en tiempo real usando Server-Sent Events (SSE), sin necesidad de recargar la página.

### Características

- Resolución DNS automática: acepta IPs o dominios (`www.ejemplo.com`)
- Tres modos de escaneo: rápido (puertos comunes), personalizado (rango definible) y completo (1-65535)
- Detección de servicio por puerto (HTTP, SSH, FTP, MySQL, etc.)
- Resultados en tiempo real vía SSE
- Tabla filtrable por estado: abierto / cerrado / filtrado
- Tiempo de respuesta por puerto
- Exportación de resultados a JSON
- Interfaz oscura y profesional, optimizada para uso en escritorio y móvil

### Estructura del proyecto

```
LukitaPort/
├── main.py          # Servidor FastAPI, endpoints SSE y estáticos
├── scanner.py       # Lógica de escaneo con sockets nativos
├── resolver.py      # Resolución DNS y validación de IP
├── frontend/
│   ├── index.html   # Interfaz web completa
│   └── styles.css   # Estilos (tema oscuro, diseño terminal)
├── requirements.txt
└── README.md
```

### Instalación

**Requisitos:**
- Python 3.10+
- pip
- (Opcional) nmap instalado en el sistema para funciones avanzadas

```bash
# Clona o descarga el proyecto
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

# Crea un entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# Instala dependencias
pip install -r requirements.txt
```

### Uso

```bash
# Arranca el servidor
uvicorn main:app --host 0.0.0.0 --port 8000

# Abre en el navegador
# http://localhost:8000
```

Una vez en la interfaz:
1. Escribe la IP o dominio objetivo en el campo de texto
2. Selecciona el modo de escaneo
3. Ajusta el timeout si es necesario
4. Pulsa **INICIAR ESCANEO** y observa los resultados en tiempo real

### Dependencias

| Paquete | Versión | Uso |
|---|---|---|
| fastapi | 0.111.0 | API y servidor web |
| uvicorn | 0.30.1 | Servidor ASGI |
| python-nmap | 0.7.1 | Detección avanzada de servicios |

---

## English

### What is LukitaPort?

LukitaPort is a web-based port scanner built for learning and practicing networking and security concepts in controlled environments. Results stream in real time using Server-Sent Events (SSE), no page refresh required.

### Features

- Automatic DNS resolution: accepts IPs or domains (`www.example.com`)
- Three scan modes: quick (common ports), custom (user-defined range), full (1-65535)
- Service detection per port (HTTP, SSH, FTP, MySQL, etc.)
- Real-time results via SSE
- Filterable table by state: open / closed / filtered
- Response time per port
- JSON export
- Dark, professional UI optimized for desktop and mobile

### Project Structure

```
LukitaPort/
├── main.py          # FastAPI server, SSE and static endpoints
├── scanner.py       # Scanning logic using native sockets
├── resolver.py      # DNS resolution and IP validation
├── frontend/
│   ├── index.html   # Full web interface
│   └── styles.css   # Styles (dark theme, terminal design)
├── requirements.txt
└── README.md
```

### Installation

**Requirements:**
- Python 3.10+
- pip
- (Optional) nmap installed on the system for advanced features

```bash
# Clone or download the project
git clone https://github.com/jaimefg1888/LukitaPort
cd LukitaPort

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Start the server
uvicorn main:app --host 0.0.0.0 --port 8000

# Open in browser
# http://localhost:8000
```

Once in the interface:
1. Enter the target IP or domain
2. Select a scan mode
3. Adjust timeout if needed
4. Click **INICIAR ESCANEO** and watch results stream in real time

### Dependencies

| Package | Version | Purpose |
|---|---|---|
| fastapi | 0.111.0 | API and web server |
| uvicorn | 0.30.1 | ASGI server |
| python-nmap | 0.7.1 | Advanced service detection |

---

## Legal Warning / Advertencia legal

**ES:** Este software se proporciona con fines educativos únicamente. El autor no asume ninguna responsabilidad por el uso indebido de esta herramienta. Antes de escanear cualquier sistema, asegúrate de tener autorización por escrito del propietario. El escaneo no autorizado puede constituir un delito penal en muchos países.

**EN:** This software is provided for educational purposes only. The author takes no responsibility for misuse of this tool. Before scanning any system, ensure you have written authorization from the owner. Unauthorized scanning may constitute a criminal offense in many jurisdictions.

---

*jaimefg1888 — Built with Python + FastAPI + vanilla JS*
