"""
scanner.py — LukitaPort v2.0
Async port scanning with concurrency profiles: stealth / normal / aggressive.
"""

import asyncio
import socket
import time
from typing import AsyncGenerator, Optional


# ─── Port metadata ────────────────────────────────────────────────────────────

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

# ─── Scan profiles ─────────────────────────────────────────────────────────────
#
# stealth    — low concurrency + inter-port delay to evade IDS/firewalls
# normal     — balanced concurrency, no delay
# aggressive — maximum concurrency, maximum speed
#
PROFILES = {
    "stealth":    {"max_concurrent": 10,   "inter_delay": 0.5},
    "normal":     {"max_concurrent": 100,  "inter_delay": 0.0},
    "aggressive": {"max_concurrent": 1000, "inter_delay": 0.0},
}


def get_service(port: int) -> str:
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


# ─── Banner probe strategy ────────────────────────────────────────────────────

_BANNER_STRATEGY: dict[int, tuple[str, Optional[bytes]]] = {
    80:    ("probe",  b"HEAD / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    8080:  ("probe",  b"HEAD / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    8888:  ("probe",  b"HEAD / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    443:   ("skip",   None),
    8443:  ("skip",   None),
    3389:  ("skip",   None),
    445:   ("skip",   None),
    139:   ("skip",   None),
    1433:  ("skip",   None),
    1521:  ("skip",   None),
    3306:  ("skip",   None),
    5432:  ("skip",   None),
    27017: ("skip",   None),
    9200:  ("probe",  b"GET / HTTP/1.0\r\nHost: ?\r\n\r\n"),
    21:    ("read",   None),
    22:    ("read",   None),
    23:    ("read",   None),
    25:    ("read",   None),
    110:   ("read",   None),
    143:   ("read",   None),
    6379:  ("probe",  b"PING\r\n"),
    5900:  ("read",   None),
    465:   ("skip",   None),
    587:   ("read",   None),
    993:   ("skip",   None),
    995:   ("skip",   None),
}

_DEFAULT_STRATEGY = ("read", None)
_BANNER_TIMEOUT   = 0.8


async def _grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
) -> Optional[str]:
    strategy, probe = _BANNER_STRATEGY.get(port, _DEFAULT_STRATEGY)

    if strategy == "skip":
        return None

    try:
        if strategy == "probe" and probe:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=0.3)

        raw = await asyncio.wait_for(reader.read(512), timeout=_BANNER_TIMEOUT)
        if not raw:
            return None

        if strategy == "probe" and probe and (probe.startswith(b"HEAD") or probe.startswith(b"GET")):
            first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace").strip()
            return first_line[:120] if first_line else None

        banner = raw.decode("utf-8", errors="replace").strip()
        banner = " ".join(banner.split())
        return banner[:120] if banner else None

    except (asyncio.TimeoutError, OSError, Exception):
        return None


# ─── Async core ───────────────────────────────────────────────────────────────

async def _scan_port_async(ip: str, port: int, timeout: float) -> dict:
    result = {
        "port": port,
        "state": "closed",
        "service": get_service(port),
        "response_time_ms": None,
        "version": None,
        "banner": None,
    }

    loop = asyncio.get_event_loop()
    start = loop.time()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        elapsed = round((loop.time() - start) * 1000, 2)
        result["state"] = "open"
        result["response_time_ms"] = elapsed

        banner = await _grab_banner(reader, writer, port)
        if banner:
            result["banner"] = banner

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    except asyncio.TimeoutError:
        result["state"] = "filtered"
        result["response_time_ms"] = round((loop.time() - start) * 1000, 2)
    except ConnectionRefusedError:
        result["state"] = "closed"
        result["response_time_ms"] = round((loop.time() - start) * 1000, 2)
    except OSError:
        result["state"] = "filtered"

    return result


async def scan_ports_stream(
    ip: str,
    ports: list,
    timeout: float = 1.0,
    max_concurrent: int = 500,
    inter_delay: float = 0.0,
) -> AsyncGenerator[dict, None]:
    """
    Async generator that yields port scan results as they complete.

    profile       max_concurrent   inter_delay
    ─────────     ──────────────   ───────────
    stealth             10            0.5 s   ← IDS evasion
    normal             100            0.0 s
    aggressive        1000            0.0 s   ← full speed
    """
    total     = len(ports)
    semaphore = asyncio.Semaphore(max_concurrent)
    completed = 0
    lock      = asyncio.Lock()

    async def scan_with_sem(port: int) -> dict:
        async with semaphore:
            res = await _scan_port_async(ip, port, timeout)
            if inter_delay > 0:
                await asyncio.sleep(inter_delay)
            return res

    tasks = {asyncio.create_task(scan_with_sem(p)): p for p in ports}

    for coro in asyncio.as_completed(tasks.keys()):
        result = await coro
        async with lock:
            completed += 1
            result["progress"] = round((completed / total) * 100, 1)
            result["scanned"]  = completed
            result["total"]    = total
        yield result


# ─── Fingerprinting via nmap ──────────────────────────────────────────────────

def fingerprint_ports(ip: str, ports: list, timeout: float = 3.0) -> dict:
    results = {}
    try:
        import nmap, shutil, os, sys
        nm = nmap.PortScanner()

        if sys.platform == "win32":
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


# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_port_range(mode: str, port_start: int = None, port_end: int = None) -> list:
    if mode == "quick":
        return COMMON_PORTS
    elif mode == "full":
        return list(range(1, 65536))
    elif mode == "custom" and port_start is not None and port_end is not None:
        return list(range(port_start, port_end + 1))
    return COMMON_PORTS
