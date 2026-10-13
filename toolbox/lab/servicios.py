"""Salud de los servicios del laboratorio."""

from __future__ import annotations

import json
import smtplib
from collections.abc import Callable
from urllib.request import urlopen

from lab import dns, mailpit
from lab.config import ATACANTE_API, EMISOR, RECEPTOR, VICTIM_DOMAIN


def _smtp_banner(host: str) -> str:
    with smtplib.SMTP(host, 25, timeout=5) as conn:
        code, _ = conn.noop()
    if code != 250:
        raise RuntimeError(f"respondió {code}")
    return "acepta conexiones SMTP"


def _dns() -> str:
    serial = dns.soa_serial(VICTIM_DOMAIN)
    if serial is None:
        raise RuntimeError(f"no responde la zona {VICTIM_DOMAIN}")
    return f"sirve {VICTIM_DOMAIN} (serial {serial})"


def _mailpit() -> str:
    total = mailpit.info().get("Messages", 0)
    return f"{total} correo{'' if total == 1 else 's'} en la bandeja"


def _atacante() -> str:
    with urlopen(f"{ATACANTE_API}/salud", timeout=5) as resp:
        json.load(resp)
    return "listo para lanzar ataques"


CHECKS: dict[str, tuple[str, Callable[[], str]]] = {
    "dns": ("Servidor DNS (CoreDNS)", _dns),
    "emisor": ("Servidor de salida del banco", lambda: _smtp_banner(EMISOR)),
    "receptor": ("MX del banco (Postfix + Rspamd)", lambda: _smtp_banner(RECEPTOR)),
    "mailpit": ("Bandeja web", _mailpit),
    "atacante": ("Atacante", _atacante),
}


def check_all() -> list[tuple[str, str, bool, str]]:
    """(servicio, función, ok, detalle) para cada servicio."""
    results = []
    for name, (role, check) in CHECKS.items():
        try:
            results.append((name, role, True, check()))
        except Exception as error:  # noqa: BLE001 (cualquier fallo = servicio no disponible)
            results.append((name, role, False, str(error) or type(error).__name__))
    return results
