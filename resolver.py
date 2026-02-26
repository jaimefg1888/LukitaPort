"""
resolver.py — DNS resolution and IP validation
jaimefg1888 | LukitaPort
"""

import socket
import re


def is_valid_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def resolve_target(target: str) -> dict:
    """
    Acepta un dominio o IP y devuelve la IP resuelta junto con metadatos.
    Si ya es una IP válida, simplemente la retorna sin resolver nada.
    """
    target = target.strip()

    if is_valid_ip(target):
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except socket.herror:
            hostname = None
        return {
            "input": target,
            "ip": target,
            "hostname": hostname,
            "resolved": False,
            "error": None,
        }

    # Es un dominio, intentamos resolver
    try:
        ip = socket.gethostbyname(target)
        return {
            "input": target,
            "ip": ip,
            "hostname": target,
            "resolved": True,
            "error": None,
        }
    except socket.gaierror as e:
        return {
            "input": target,
            "ip": None,
            "hostname": None,
            "resolved": False,
            "error": str(e),
        }
