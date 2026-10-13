"""Tabla de verdad de CLAUDE.md (sección 6): el contrato del laboratorio.

`TRUTH_TABLE` copia la tabla tal cual. Cada fase agrega sus celdas a `IMPLEMENTED`
cuando existen el escenario y el envío correspondientes.

Resultado esperado:
  E        entregado en Mailpit
  E+marca  entregado con marca de spam o cuarentena visible
  R        rechazado con un SMTP 5xx
Los fragmentos (p. ej. "spf=none") deben aparecer en Authentication-Results.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from lab import escenarios, mailpit
from lab.envios import launch_attack, send_legit


@dataclass(frozen=True)
class Expected:
    outcome: str  # "E", "E+marca" o "R"
    auth: tuple[str, ...] = ()


def cell(text: str) -> Expected:
    outcome, *auth = text.split()
    return Expected(outcome, tuple(a for a in auth if "=" in a))


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

# Celdas ya construidas (envío, escenario). Fase 2: escenario 0, legítimo y A1.
IMPLEMENTED = [
    ("legit", "0"),
    ("A1", "0"),
]


def expected(sender: str, scenario: str) -> Expected:
    return cell(TRUTH_TABLE[sender][COLUMNS.index(scenario)])


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
        code, message_id = result.code, result.message_id
    else:
        attack = launch_attack(sender)
        code, message_id = attack["code"], attack["message_id"]

    if want.outcome == "R":
        assert 500 <= code < 600, f"{sender}/{scenario}: se esperaba rechazo 5xx, llegó {code}"
        assert mailpit.find_by_message_id(message_id) is None
        return

    assert 200 <= code < 300, f"{sender}/{scenario}: SMTP {code}, se esperaba aceptación"
    message = mailpit.wait_for_message_id(message_id)
    assert message, f"{sender}/{scenario}: no llegó a Mailpit"

    auth = mailpit.headers(message["ID"]).get("Authentication-Results", [""])[0]
    for fragment in want.auth:
        assert fragment in auth, f"{sender}/{scenario}: falta «{fragment}» en «{auth}»"
    # "E+marca" se verificará en la fase 5 (DMARC quarantine).
    assert want.outcome == "E", f"Resultado {want.outcome} aún no implementado en el test"


def test_tabla_copiada_completa() -> None:
    """La tabla del test tiene todas las filas y columnas de CLAUDE.md."""
    assert set(TRUTH_TABLE) == {"legit", "A1", "A2", "A3", "A4", "A5", "A6"}
    assert all(len(row) == len(COLUMNS) for row in TRUTH_TABLE.values())
