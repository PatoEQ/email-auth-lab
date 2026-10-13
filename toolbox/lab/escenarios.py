"""Activación de escenarios: zonas DNS en el volumen compartido, sin docker.sock."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

import renderizar_zonas as zonas  # compartido con `init` (ver toolbox/Dockerfile)

from lab import dns
from lab.config import DKIM_SELECTOR, ESTADO_DIR, VICTIM_DOMAIN, ZONAS_DIR

ESCENARIOS = zonas.ESCENARIOS

# Qué significa cada escenario, en una frase para la audiencia.
MEANING: dict[str, str] = {
    "0": (
        "bancoseguro.test no publica SPF, DKIM ni DMARC. El receptor no tiene cómo saber "
        "quién puede enviar en nombre del banco: cualquiera puede escribir "
        "«director@bancoseguro.test» y el correo llega."
    ),
}

# Registros de autenticación que mostramos al activar o consultar el estado.
AUTH_RECORDS = (
    ("SPF", VICTIM_DOMAIN),
    ("DKIM", f"{DKIM_SELECTOR}._domainkey.{VICTIM_DOMAIN}"),
    ("DMARC", f"_dmarc.{VICTIM_DOMAIN}"),
)


@dataclass
class Activation:
    state: dict[str, Any]
    previous: str | None
    added: list[str]
    removed: list[str]
    propagated: bool


def current_state() -> dict[str, Any]:
    return zonas.leer_estado(ESTADO_DIR)


def _records(zone_text: str) -> set[str]:
    """Registros de la zona sin comentarios ni el bloque SOA (que cambia en cada activación)."""
    text = re.sub(r"IN SOA[^)]*\)", "", zone_text)
    lines = (re.sub(r";.*", "", line) for line in text.splitlines())
    return {" ".join(line.split()) for line in lines if line.strip() and not line.startswith("$")}


def _active_zone() -> str:
    path = ZONAS_DIR / "activas" / f"db.{VICTIM_DOMAIN}"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def activate(escenario_id: str, timeout: float = 15.0) -> Activation:
    """Publica el escenario y espera a que CoreDNS sirva el serial nuevo."""
    previous = current_state().get("escenario")
    before = _records(_active_zone())
    state = zonas.activar(escenario_id, ZONAS_DIR, ESTADO_DIR)
    after = _records(_active_zone())

    deadline = time.monotonic() + timeout
    propagated = False
    while time.monotonic() < deadline:
        if dns.soa_serial(VICTIM_DOMAIN) == state["serial"]:
            propagated = True
            break
        time.sleep(0.5)

    return Activation(
        state=state,
        previous=str(previous) if previous is not None else None,
        added=sorted(after - before),
        removed=sorted(before - after),
        propagated=propagated,
    )


def published_records() -> list[tuple[str, str, list[str]]]:
    """(tipo, nombre, valores TXT relevantes) tal como los responde el DNS ahora."""
    result = []
    for kind, name in AUTH_RECORDS:
        answers = dns.dig(name, "TXT")
        if kind == "SPF":
            answers = [a for a in answers if a.startswith("v=spf1")]
        result.append((kind, name, answers))
    return result
