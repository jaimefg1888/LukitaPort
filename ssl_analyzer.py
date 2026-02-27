import ssl
import socket
from datetime import datetime, timezone
from typing import Optional


WEAK_CIPHERS = {"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5", "ADH", "AECDH"}
DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


def _parse_cert_name(rdns) -> dict:
    result = {}
    for rdn in rdns:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_san(cert: dict) -> list:
    return [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]


def _days_until(dt: datetime) -> int:
    return (dt - datetime.now(timezone.utc)).days


def analyze_ssl(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    result = {
        "hostname": hostname, "port": port,
        "valid": False, "error": None,
        "subject": {}, "issuer": {},
        "not_before": None, "not_after": None,
        "days_until_expiry": None,
        "expired": False, "expiring_soon": False,
        "sans": [], "cipher": None, "protocol": None, "bits": None,
        "weak_cipher": False, "deprecated_protocol": False, "self_signed": False,
        "grade": "F", "issues": [],
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert         = tls_sock.getpeercert()
                cipher_tuple = tls_sock.cipher()
                protocol     = tls_sock.version()
    except socket.timeout:
        result["error"] = "Connection timed out"
        return result
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e.reason or str(e)}"
        return result
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
        return result
    except OSError as e:
        result["error"] = str(e)
        return result

    if not cert:
        result["error"] = "No certificate returned"
        return result

    result["valid"]   = True
    result["subject"] = _parse_cert_name(cert.get("subject", ()))
    result["issuer"]  = _parse_cert_name(cert.get("issuer", ()))

    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before = datetime.strptime(cert.get("notBefore", ""), fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(cert.get("notAfter", ""),  fmt).replace(tzinfo=timezone.utc)
        result["not_before"] = not_before.isoformat()
        result["not_after"]  = not_after.isoformat()
        days = _days_until(not_after)
        result["days_until_expiry"] = days
        result["expired"]       = days < 0
        result["expiring_soon"] = 0 <= days < 30
        if result["expired"]:
            result["issues"].append("Certificate is EXPIRED")
        elif result["expiring_soon"]:
            result["issues"].append(f"Certificate expires in {days} days")
    except Exception:
        pass

    result["sans"] = _parse_san(cert)

    if cipher_tuple:
        cipher_name, tls_version, bits = cipher_tuple
        result["cipher"]   = cipher_name
        result["protocol"] = protocol or tls_version
        result["bits"]     = bits
        if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
            result["weak_cipher"] = True
            result["issues"].append(f"Weak cipher: {cipher_name}")
        if result["protocol"] in DEPRECATED_PROTOCOLS:
            result["deprecated_protocol"] = True
            result["issues"].append(f"Deprecated protocol: {result['protocol']}")

    if result["subject"] == result["issuer"]:
        result["self_signed"] = True
        result["issues"].append("Self-signed certificate")

    if result["expired"]:
        result["grade"] = "F"
    elif result["deprecated_protocol"]:
        result["grade"] = "C" if not result["weak_cipher"] else "F"
    elif result["weak_cipher"] or result["self_signed"]:
        result["grade"] = "C"
    elif result["expiring_soon"]:
        result["grade"] = "B"
    elif not result["issues"]:
        result["grade"] = "A" if (result.get("bits") or 0) >= 128 else "B"
    else:
        result["grade"] = "D"

    return result


def analyze_ssl_for_ports(hostname: str, open_ports: list, timeout: float = 8.0) -> dict:
    target_ports = [p for p in [443, 8443] if p in open_ports]
    if not target_ports:
        return {"error": "No HTTPS ports detected", "results": {}}
    return {"results": {port: analyze_ssl(hostname, port, timeout) for port in target_ports}}
