"""
ssl_analyzer.py — LukitaPort
Analyzes SSL/TLS certificates and cipher configuration for open HTTPS ports.
"""

import ssl
import socket
import json
from datetime import datetime, timezone
from typing import Optional


WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "ADH", "AECDH",
}

DEPRECATED_PROTOCOLS = {
    "SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1",
}


def _parse_cert_name(rdns) -> dict:
    """Converts RDNs tuple to a flat dict."""
    result = {}
    for rdn in rdns:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_san(cert: dict) -> list:
    """Extracts Subject Alternative Names from cert dict."""
    san_ext = cert.get("subjectAltName", ())
    return [value for kind, value in san_ext if kind == "DNS"]


def _days_until(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    delta = dt - now
    return delta.days


def analyze_ssl(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    """
    Connects to hostname:port over TLS and extracts certificate/cipher info.

    Returns a dict with:
      - valid: bool
      - error: str | None
      - subject, issuer: dicts
      - not_before, not_after: ISO strings
      - days_until_expiry: int
      - expired: bool
      - expiring_soon: bool (< 30 days)
      - sans: list of DNS SANs
      - cipher: str
      - protocol: str
      - bits: int
      - weak_cipher: bool
      - deprecated_protocol: bool
      - self_signed: bool
      - grade: str  (A/B/C/F)
    """
    result = {
        "hostname": hostname,
        "port": port,
        "valid": False,
        "error": None,
        "subject": {},
        "issuer": {},
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "expired": False,
        "expiring_soon": False,
        "sans": [],
        "cipher": None,
        "protocol": None,
        "bits": None,
        "weak_cipher": False,
        "deprecated_protocol": False,
        "self_signed": False,
        "grade": "F",
        "issues": [],
    }

    # ── Connect and get cert ─────────────────────────────────────────────────
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we analyze cert ourselves

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher_tuple = tls_sock.cipher()     # (name, protocol, bits)
                protocol = tls_sock.version()
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

    result["valid"] = True

    # ── Subject & Issuer ─────────────────────────────────────────────────────
    result["subject"] = _parse_cert_name(cert.get("subject", ()))
    result["issuer"]  = _parse_cert_name(cert.get("issuer", ()))

    # ── Validity dates ───────────────────────────────────────────────────────
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter", "")
        not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
        not_after  = datetime.strptime(not_after_str,  fmt).replace(tzinfo=timezone.utc)
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

    # ── SANs ─────────────────────────────────────────────────────────────────
    result["sans"] = _parse_san(cert)

    # ── Cipher & Protocol ────────────────────────────────────────────────────
    if cipher_tuple:
        cipher_name, tls_version, bits = cipher_tuple
        result["cipher"]   = cipher_name
        result["protocol"] = protocol or tls_version
        result["bits"]     = bits

        cipher_upper = cipher_name.upper()
        if any(w in cipher_upper for w in WEAK_CIPHERS):
            result["weak_cipher"] = True
            result["issues"].append(f"Weak cipher: {cipher_name}")

        if result["protocol"] in DEPRECATED_PROTOCOLS:
            result["deprecated_protocol"] = True
            result["issues"].append(f"Deprecated protocol: {result['protocol']}")

    # ── Self-signed ──────────────────────────────────────────────────────────
    subject_cn = result["subject"].get("commonName", "")
    issuer_cn  = result["issuer"].get("commonName", "")
    issuer_org = result["issuer"].get("organizationName", "")

    if result["subject"] == result["issuer"]:
        result["self_signed"] = True
        result["issues"].append("Self-signed certificate")

    # ── Grade ────────────────────────────────────────────────────────────────
    penalty = len(result["issues"])
    if result["expired"]:
        result["grade"] = "F"
    elif result["deprecated_protocol"]:
        result["grade"] = "C" if not result["weak_cipher"] else "F"
    elif result["weak_cipher"] or result["self_signed"]:
        result["grade"] = "C"
    elif result["expiring_soon"]:
        result["grade"] = "B"
    elif penalty == 0:
        bits = result.get("bits") or 0
        result["grade"] = "A" if bits >= 128 else "B"
    else:
        result["grade"] = "D"

    return result


def analyze_ssl_for_ports(hostname: str, open_ports: list, timeout: float = 8.0) -> dict:
    """
    Runs SSL analysis on all HTTPS-capable open ports.
    Returns a dict keyed by port number.
    """
    ssl_ports = [p for p in open_ports if p in (443, 8443, 8080, 8888) or p == 443]
    # Prioritize standard HTTPS ports
    target_ports = [p for p in [443, 8443] if p in open_ports]
    if not target_ports:
        return {"error": "No HTTPS ports detected", "results": {}}

    results = {}
    for port in target_ports:
        results[port] = analyze_ssl(hostname, port, timeout)

    return {"results": results}
