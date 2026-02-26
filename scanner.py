"""
scanner.py — Core port scanning logic
Usa sockets nativos para escaneo básico y python-nmap para detección avanzada.
jaimefg1888 | LukitaPort
"""

import socket
import time
from typing import Generator

# Puertos comunes con sus servicios conocidos
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017
]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Dev", 9200: "Elasticsearch", 27017: "MongoDB",
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
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = sock.connect_ex((ip, port))
        elapsed = round((time.monotonic() - start) * 1000, 2)
        result["response_time_ms"] = elapsed

        if conn == 0:
            result["state"] = "open"
        else:
            result["state"] = "closed"

        sock.close()
    except socket.timeout:
        result["state"] = "filtered"
        result["response_time_ms"] = round((time.monotonic() - start) * 1000, 2)
    except OSError:
        result["state"] = "filtered"

    return result


def get_port_range(mode: str, port_start: int = None, port_end: int = None) -> list:
    if mode == "quick":
        return COMMON_PORTS
    elif mode == "full":
        return list(range(1, 65536))
    elif mode == "custom" and port_start is not None and port_end is not None:
        return list(range(port_start, port_end + 1))
    return COMMON_PORTS


def scan_ports_stream(ip: str, ports: list, timeout: float = 1.0) -> Generator[dict, None, None]:
    """
    Generador que escanea puerto a puerto y hace yield de cada resultado.
    Diseñado para consumirse desde un SSE endpoint.
    """
    total = len(ports)
    for idx, port in enumerate(ports, start=1):
        result = scan_port(ip, port, timeout)
        result["progress"] = round((idx / total) * 100, 1)
        result["scanned"] = idx
        result["total"] = total
        yield result
