"""Activación de escenarios: zonas DNS en el volumen compartido, sin docker.sock."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

import renderizar_zonas as zonas  # compartido con `init` (ver toolbox/Dockerfile)

from lab import dns
from lab.config import DKIM_SELECTOR, ESTADO_DIR, VICTIM_DOMAIN, ZONAS_DIR, ZONE_TTL

ESCENARIOS = zonas.ESCENARIOS

# Qué significa cada escenario, en una frase para la audiencia.
MEANING: dict[str, str] = {
    "0": (
        "bancoseguro.test no publica SPF, DKIM ni DMARC. El receptor no tiene cómo saber "
        "quién puede enviar en nombre del banco: cualquiera puede escribir "
        "«director@bancoseguro.test» y el correo llega."
    ),
    "1": (
        "bancoseguro.test publica SPF: «solo 172.28.0.10 (el emisor) envía correo con "
        "nuestro dominio en el sobre; el resto, rechazar (-all)». SPF revisa el sobre "
        "(MAIL FROM), no el From: que ve el empleado: un atacante que pone su propio "
        "dominio en el sobre pasa SPF sin problema."
    ),
    "2": (
        "Además del SPF, el emisor firma cada correo con DKIM (selector s2026) y el banco "
        "publica la llave pública. El receptor puede comprobar quién firmó y que nadie "
        "modificó el correo por el camino. Pero DKIM tampoco compara el dominio que firma "
        "(d=) con el From: que ve el empleado."
    ),
    "3-none": (
        "El banco publica DMARC con p=none: «avísenme qué pasa, pero no bloqueen nada». "
        "Ahora el receptor exige alineación: SPF o DKIM deben validar el mismo dominio "
        "del From:. Los ataques salen dmarc=fail, pero se entregan. Es la etapa de "
        "observación: los reportes (rua) muestran quién envía en nombre del banco."
    ),
    "3-quarantine": (
        "Política p=quarantine: lo que falla DMARC se entrega marcado como sospechoso "
        "(en el laboratorio, con «[CUARENTENA]» en el asunto). El correo legítimo, "
        "alineado, sigue llegando limpio."
    ),
    "3-reject": (
        "Política p=reject: lo que falla DMARC se rechaza en la conversación SMTP (5xx) "
        "y nunca llega a la bandeja. A1–A4 quedan bloqueados; el correo legítimo pasa."
    ),
    "4": (
        "La misma protección que 3-reject: bancoseguro.test está blindado. Pero SPF, DKIM "
        "y DMARC solo protegen el dominio exacto. Un dominio parecido (bancos3guro.test, "
        "con su propio DMARC impecable) o un nombre visible engañoso («Director General» "
        "con una dirección cualquiera) pasan todas las verificaciones."
    ),
    "5": (
        "Igual que 3-reject, más dos lecciones de producción. 1) Un dominio que no envía "
        "correo (noenvia.test) también debe protegerse: «v=spf1 -all» y DMARC p=reject. "
        "2) El reenvío rompe SPF (cambia la IP), pero DKIM sobrevive si nadie toca el "
        "correo; una lista de correo que modifica asunto o cuerpo rompe ambos."
    ),
}

# Registros de autenticación que mostramos al activar o consultar el estado.
AUTH_RECORDS = (
    ("SPF", VICTIM_DOMAIN),
    ("DKIM", f"{DKIM_SELECTOR}._domainkey.{VICTIM_DOMAIN}"),
    ("DMARC", f"_dmarc.{VICTIM_DOMAIN}"),
)
# Dominio que no envía correo (escenario 5): se muestra solo si publica algo.
PARKED_RECORDS = (("SPF", "noenvia.test"), ("DMARC", "_dmarc.noenvia.test"))


@dataclass
class Activation:
    state: dict[str, Any]
    previous: str | None
    added: list[str]
    removed: list[str]
    propagated: bool
    waited_ttl: bool  # ¿esperamos a que caduquen las cachés DNS?
    emisor_confirmed: bool  # ¿el emisor ya aplicó la firma DKIM del escenario?


def current_state() -> dict[str, Any]:
    return zonas.leer_estado(ESTADO_DIR)


def _strip_comment(line: str) -> str:
    """Quita el comentario («; …») que no esté dentro de comillas (los TXT llevan «;»)."""
    in_quotes = False
    for i, char in enumerate(line):
        if char == '"':
            in_quotes = not in_quotes
        elif char == ";" and not in_quotes:
            return line[:i]
    return line


def _records(zone_text: str) -> set[str]:
    """Registros de la zona sin comentarios ni el bloque SOA (que cambia en cada activación)."""
    text = re.sub(r"IN SOA[^)]*\)", "", zone_text)
    lines = (_strip_comment(line) for line in text.splitlines())
    return {" ".join(line.split()) for line in lines if line.strip() and not line.startswith("$")}


def _active_records() -> set[str]:
    """Registros activos de todas las zonas. Los de otros dominios llevan el dominio
    delante, para que el resumen de cambios diga a quién pertenecen."""
    records: set[str] = set()
    for domain in zonas.DOMINIOS:
        path = ZONAS_DIR / "activas" / f"db.{domain}"
        if not path.exists():
            continue
        prefix = "" if domain == VICTIM_DOMAIN else f"({domain}) "
        records |= {prefix + r for r in _records(path.read_text(encoding="utf-8"))}
    return records


def activate(escenario_id: str, timeout: float = 15.0) -> Activation:
    """Publica el escenario y espera a que CoreDNS sirva el serial nuevo."""
    previous = current_state().get("escenario")
    before = _active_records()
    state = zonas.activar(escenario_id, ZONAS_DIR, ESTADO_DIR)
    after = _active_records()

    deadline = time.monotonic() + timeout
    propagated = False
    while time.monotonic() < deadline:
        if dns.soa_serial(VICTIM_DOMAIN) == state["serial"]:
            propagated = True
            break
        time.sleep(0.5)

    emisor_confirmed = _wait_emisor(state, deadline)

    # El receptor puede tener en caché los registros anteriores hasta que venza su TTL.
    # Si la zona cambió, esperamos ese TTL para que el próximo correo vea los nuevos.
    changed = before != after
    if changed and propagated:
        time.sleep(ZONE_TTL)

    return Activation(
        state=state,
        previous=str(previous) if previous is not None else None,
        added=sorted(after - before),
        removed=sorted(before - after),
        propagated=propagated,
        waited_ttl=changed and propagated,
        emisor_confirmed=emisor_confirmed,
    )


def emisor_state() -> dict[str, Any]:
    """Lo que el emisor confirmó haber aplicado (escribe estado/emisor.json)."""
    try:
        return json.loads((ESTADO_DIR / "emisor.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _wait_emisor(state: dict[str, Any], deadline: float) -> bool:
    """Espera a que el emisor aplique el escenario (revisa estado/ cada segundo)."""
    while True:
        applied = emisor_state()
        if applied.get("serial") == state["serial"]:
            return applied.get("firma_dkim") == state["firma_dkim"]
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.3)


def published_records() -> list[tuple[str, str, list[str]]]:
    """(tipo, nombre, valores TXT relevantes) tal como los responde el DNS ahora."""
    result = []
    for kind, name in AUTH_RECORDS:
        answers = dns.dig(name, "TXT")
        if kind == "SPF":
            answers = [a for a in answers if a.startswith("v=spf1")]
        result.append((kind, name, answers))
    for kind, name in PARKED_RECORDS:
        answers = dns.dig(name, "TXT")
        if answers:
            result.append((kind, name, answers))
    return result
