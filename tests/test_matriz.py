"""Tabla de verdad de CLAUDE.md (sección 6): el contrato del laboratorio.

`TRUTH_TABLE` copia la tabla tal cual. Cada fase agrega sus celdas a `IMPLEMENTED`
cuando existen el escenario y el envío correspondientes.

Resultado esperado:
  E        entregado en Mailpit
  E+marca  entregado con marca de spam o cuarentena visible
  R        rechazado con un SMTP 5xx
Los fragmentos (p. ej. "spf=none") deben aparecer en Authentication-Results.
Un dominio entre paréntesis, p. ej. "spf=pass (atacante.test)", indica para qué dominio
se obtuvo ese resultado: también se verifica en Authentication-Results.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from lab import escenarios, mailpit
from lab.envios import launch_attack, send_legit


@dataclass(frozen=True)
class Expected:
    outcome: str  # "E", "E+marca" o "R"
    auth: tuple[str, ...] = ()
    domain: str | None = None  # dominio entre paréntesis, si la celda lo indica


def cell(text: str) -> Expected:
    domain = re.search(r"\(([^)]+)\)", text)
    outcome, *auth = re.sub(r"\([^)]*\)", "", text).split()
    return Expected(outcome, tuple(auth), domain.group(1) if domain else None)


# Dónde aparece el dominio de cada método en Authentication-Results.
DOMAIN_FIELD = {"spf": "smtp.mailfrom=", "dkim": "header.d=", "dmarc": "header.from="}


COLUMNS = ("0", "1", "2", "3-none", "3-quarantine", "3-reject")
# fmt: off
TRUTH_TABLE: dict[str, tuple[str, ...]] = {
    "legit": ("E spf=none", "E spf=pass", "E dkim=pass", "E dmarc=pass", "E dmarc=pass", "E dmarc=pass"),  # noqa: E501
    "A1":    ("E spf=none", "E spf=fail", "E spf=fail", "E dmarc=fail", "E+marca", "R"),
    "A2":    ("E", "E spf=pass", "E", "E dmarc=fail", "E+marca", "R"),
    "A3":    ("E", "E spf=fail", "E dkim=fail", "E dmarc=fail", "E+marca", "R"),
    "A4":    ("E", "E", "E dkim=pass", "E dmarc=fail", "E+marca", "R"),
    "A5":    ("E", "E", "E", "E", "E", "E dmarc=pass"),
    "A6":    ("E", "E", "E", "E", "E", "E"),
}
# fmt: on

# Los escenarios 4 y 5 repiten la columna 3-reject (CLAUDE.md, sección 6).
SAME_AS = {"4": "3-reject", "5": "3-reject"}

# Celdas ya construidas (envío, escenario), agrupadas por escenario para cambiar poco.
# Fase 2: columna 0 (legítimo, A1). Fase 3: + columna 1 y A2. Fase 4: + columna 2, A3 y A4.
# Fase 5: + columnas 3-*. Fase 6: + A5, A6 y los escenarios 4 y 5.
# El legítimo va primero en cada columna: A3 altera el último correo legítimo.
IMPLEMENTED = [
    (sender, scenario)
    for scenario in ("0", "1", "2", "3-none", "3-quarantine", "3-reject", "4", "5")
    for sender in TRUTH_TABLE
]

# Marca visible de cuarentena (receptor/rspamd/actions.conf).
QUARANTINE_TAG = "[CUARENTENA]"


def expected(sender: str, scenario: str) -> Expected:
    column = SAME_AS.get(scenario, scenario)
    return cell(TRUTH_TABLE[sender][COLUMNS.index(column)])


@pytest.fixture(scope="module", autouse=True)
def restore_scenario_0() -> Iterator[None]:
    yield
    escenarios.activate("0")


@pytest.mark.parametrize(("sender", "scenario"), IMPLEMENTED, ids=lambda v: v)
def test_tabla_de_verdad(sender: str, scenario: str) -> None:
    want = expected(sender, scenario)
    activation = escenarios.activate(scenario)
    assert activation.propagated, "CoreDNS no publicó el serial nuevo a tiempo"

    if sender == "legit":
        result = send_legit()
        code, message_id, queue = result.code, result.message_id, None
    else:
        attack = launch_attack(sender)
        code, message_id = attack["code"], attack["message_id"]
        queue = mailpit.queue_id(attack["reply"])  # A3 reutiliza el Message-ID original

    if want.outcome == "R":
        # Un 5xx en la conversación SMTP significa que el receptor no lo aceptó.
        assert 500 <= code < 600, f"{sender}/{scenario}: se esperaba rechazo 5xx, llegó {code}"
        return

    assert 200 <= code < 300, f"{sender}/{scenario}: SMTP {code}, se esperaba aceptación"
    message = mailpit.wait_for_message_id(message_id, queue)
    assert message, f"{sender}/{scenario}: no llegó a Mailpit"

    auth = mailpit.headers(message["ID"]).get("Authentication-Results", [""])[0]
    for fragment in want.auth:
        assert fragment in auth, f"{sender}/{scenario}: falta «{fragment}» en «{auth}»"
    if want.domain:
        method = want.auth[0].split("=")[0]
        pattern = rf"{DOMAIN_FIELD[method]}\S*{re.escape(want.domain)}\b"
        assert re.search(pattern, auth), f"{sender}/{scenario}: {method} no es de {want.domain}"
    marked = message["Subject"].startswith(QUARANTINE_TAG)
    if want.outcome == "E+marca":
        assert marked, f"{sender}/{scenario}: se esperaba la marca de cuarentena en el asunto"
    else:
        assert not marked, f"{sender}/{scenario}: llegó marcado y la tabla dice entrega limpia"


def test_lectura_de_celdas() -> None:
    assert cell("E spf=pass (atacante.test)") == Expected("E", ("spf=pass",), "atacante.test")
    assert cell("E+marca") == Expected("E+marca")
    assert cell("R") == Expected("R")


def test_tabla_copiada_completa() -> None:
    """La tabla del test tiene todas las filas y columnas de CLAUDE.md."""
    assert set(TRUTH_TABLE) == {"legit", "A1", "A2", "A3", "A4", "A5", "A6"}
    assert all(len(row) == len(COLUMNS) for row in TRUTH_TABLE.values())
