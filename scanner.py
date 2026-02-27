import socket
import time
from typing import Generator


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017
]

SERVICE_MAP = {
    21: "FTP",    22: "SSH",        23: "Telnet",     25: "SMTP",
    53: "DNS",    80: "HTTP",       110: "POP3",      111: "RPC",
    135: "MSRPC", 139: "NetBIOS",   143: "IMAP",      443: "HTTPS",
    445: "SMB",   465: "SMTPS",     587: "SMTP/TLS",  993: "IMAPS",
    995: "POP3S", 1433: "MSSQL",    1521: "Oracle DB", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP",     5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Dev",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def get_service(port: int) -> str:
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    start = time.monotonic()
    result = {
        "port": port,
        "state": "closed",
        "service": get_service(port),
        "response_time_ms": None,
        "version": None,
        "banner": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = sock.connect_ex((ip, port))
        elapsed = round((time.monotonic() - start) * 1000, 2)
        result["response_time_ms"] = elapsed

        if conn == 0:
            result["state"] = "open"
            # Intentar capturar banner básico
            try:
                sock.settimeout(0.8)
                banner_raw = sock.recv(256)
                banner = banner_raw.decode("utf-8", errors="replace").strip()
                if banner:
                    result["banner"] = banner[:120]
            except Exception:
                pass
        else:
            result["state"] = "closed"
        sock.close()
    except socket.timeout:
        result["state"] = "filtered"
        result["response_time_ms"] = round((time.monotonic() - start) * 1000, 2)
    except OSError:
        result["state"] = "filtered"

    return result


def fingerprint_ports(ip: str, ports: list, timeout: float = 3.0) -> dict:
    """
    Usa python-nmap para detectar versiones de servicio en los puertos abiertos.
    Devuelve dict {port: {version, product, extrainfo, cpe}}
    Requiere nmap instalado en el sistema.
    """
    results = {}
    try:
        import nmap
        import shutil
        import os
        import sys

        nm = nmap.PortScanner()

        # En Windows, nmap puede no estar en PATH — buscar rutas comunes
        if sys.platform == 'win32':
            win_paths = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\nmap\nmap.exe",
            ]
            nmap_path = shutil.which("nmap")
            if not nmap_path:
                for p in win_paths:
                    if os.path.isfile(p):
                        nmap_path = p
                        break
            if nmap_path:
                nm = nmap.PortScanner(nmap_search_path=(nmap_path,))

        ports_str = ",".join(str(p) for p in ports)
        nm.scan(
            hosts=ip,
            ports=ports_str,
            arguments=f"-sV --version-intensity 5 --host-timeout {int(timeout * len(ports))}s -T4"
        )
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    svc = nm[ip][proto][port]
                    results[port] = {
                        "product":   svc.get("product", ""),
                        "version":   svc.get("version", ""),
                        "extrainfo": svc.get("extrainfo", ""),
                        "cpe":       svc.get("cpe", ""),
                        "name":      svc.get("name", ""),
                    }
    except ImportError:
        results["_error"] = "nmap_not_installed"
    except Exception as e:
        err_str = str(e)
        if "nmap program was not found" in err_str or "not found in path" in err_str.lower():
            results["_error"] = "nmap_not_installed"
        else:
            results["_error"] = err_str
    return results


def get_port_range(mode: str, port_start: int = None, port_end: int = None) -> list:
    if mode == "quick":
        return COMMON_PORTS
    elif mode == "full":
        return list(range(1, 65536))
    elif mode == "custom" and port_start is not None and port_end is not None:
        return list(range(port_start, port_end + 1))
    return COMMON_PORTS


def scan_ports_stream(ip: str, ports: list, timeout: float = 1.0) -> Generator[dict, None, None]:
    total = len(ports)
    for idx, port in enumerate(ports, start=1):
        result = scan_port(ip, port, timeout)
        result["progress"] = round((idx / total) * 100, 1)
        result["scanned"] = idx
        result["total"] = total
        yield result
