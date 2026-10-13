"""Fase 5: DMARC. Escenarios 3-*, aplicación de la política, atacar --todos y reportes."""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

import pytest
from lab import escenarios, mailpit, reportes
from lab.envios import launch_attack, send_legit

POLICIES = ("none", "quarantine", "reject")
EXAMPLES = Path("/lab/reportes/ejemplos")
TEST_NET_1 = ipaddress.ip_network("192.0.2.0/24")


def lab(*args: str) -> subprocess.CompletedProcess[str]:
    # Terminal ancha: que rich no parta las celdas de las tablas en varias líneas.
    env = {**os.environ, "COLUMNS": "200"}
    return subprocess.run(["lab", *args], capture_output=True, text=True, timeout=180, env=env)


def flat(text: str) -> str:
    return " ".join(text.split())


def delivered_auth(message_id: str, reply: str | None = None) -> tuple[str, str]:
    queue = mailpit.queue_id(reply) if reply else None
    message = mailpit.wait_for_message_id(message_id, queue)
    assert message, "el correo no llegó a Mailpit"
    return message["Subject"], mailpit.headers(message["ID"])["Authentication-Results"][0]


@pytest.fixture(scope="module", autouse=True)
def restore_scenario_0() -> Iterator[None]:
    yield
    escenarios.activate("0")


# --- escenarios -------------------------------------------------------------------


@pytest.mark.parametrize("policy", POLICIES)
def test_escenarios_3_publican_dmarc(policy: str) -> None:
    result = escenarios.activate(f"3-{policy}")
    assert result.propagated and result.emisor_confirmed
    assert result.state["firma_dkim"] is True
    records = {kind: values for kind, _, values in escenarios.published_records()}
    assert records["SPF"] == ["v=spf1 ip4:172.28.0.10 -all"]
    assert len(records["DKIM"]) == 1
    assert records["DMARC"] == [f"v=DMARC1; p={policy}; rua=mailto:dmarc-reportes@bancoseguro.test"]


# --- aplicación de la política en el receptor ------------------------------------------


def test_legitimo_pasa_dmarc_alineado() -> None:
    escenarios.activate("3-reject")
    result = send_legit()
    subject, auth = delivered_auth(result.message_id)
    assert not subject.startswith("[CUARENTENA]")
    assert "dmarc=pass" in auth and "header.from=bancoseguro.test" in auth
    assert "policy=reject" in auth


def test_none_solo_observa() -> None:
    escenarios.activate("3-none")
    attack = launch_attack("A1")
    assert attack["accepted"]
    subject, auth = delivered_auth(attack["message_id"], attack["reply"])
    assert subject == "Transferencia urgente"
    assert "dmarc=fail" in auth and "policy=none" in auth


def test_quarantine_marca_el_asunto() -> None:
    escenarios.activate("3-quarantine")
    attack = launch_attack("A4")
    assert attack["accepted"]
    subject, auth = delivered_auth(attack["message_id"], attack["reply"])
    assert subject == "[CUARENTENA] Transferencia urgente"
    assert "DKIM not aligned" in auth, "A4 tiene firma válida, pero de otro dominio"


def test_reject_responde_5xx_con_motivo() -> None:
    escenarios.activate("3-reject")
    attack = launch_attack("A2")
    assert attack["code"] == 554
    assert "DMARC" in attack["reply"]
    assert not attack["accepted"]


def test_puntaje_antispam_no_marca_ni_rechaza() -> None:
    """A3 falla SPF y DKIM: sin DMARC (escenario 2) debe llegar limpio, no por puntaje."""
    escenarios.activate("2")
    send_legit()
    attack = launch_attack("A3")
    assert attack["accepted"]
    subject, auth = delivered_auth(attack["message_id"], attack["reply"])
    assert not subject.startswith("[CUARENTENA]")
    assert "spf=fail" in auth and "dkim=fail" in auth


# --- CLI ------------------------------------------------------------------------------


def test_cli_atacar_todos_en_reject() -> None:
    escenarios.activate("3-reject")
    proc = lab("atacar", "--todos")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = flat(proc.stdout)
    for attack_id in ("A1", "A2", "A3", "A4", "A5", "A6"):
        assert f"{attack_id} ·" in text
    # A1–A4 rechazados; A5 y A6 (fase 6) pasan incluso con p=reject: son los límites.
    assert text.count("RECHAZADO") == 4
    assert text.count("Llegó a la bandeja") == 2


def test_cli_explica_quarantine() -> None:
    escenarios.activate("3-quarantine")
    proc = lab("atacar", "A1")
    text = flat(proc.stdout)
    assert "Llegó MARCADO como sospechoso" in text
    assert "p=quarantine" in text


def test_cli_reportes() -> None:
    proc = lab("reportes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = flat(proc.stdout)
    for category in ("Legítimo", "Reenvío", "Servicio sin alinear", "Posible suplantación"):
        assert category in text
    assert "1590 de 2091 correos pasan DMARC" in text


def test_reporte_interpretado() -> None:
    (path,) = reportes.available()
    report = reportes.parse(path)
    assert (report.domain, report.policy) == ("bancoseguro.test", "none")
    verdicts = {row.source_ip: row.verdict()[0] for row in report.rows}
    assert verdicts == {
        "192.0.2.10": "Legítimo",
        "192.0.2.25": "Reenvío",
        "192.0.2.140": "Servicio sin alinear",
        "192.0.2.77": "Posible suplantación",
    }


# --- el XML de ejemplo es 100 % ficticio --------------------------------------------


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.xml")), ids=lambda p: p.name)
def test_reporte_de_ejemplo_es_ficticio(path: Path) -> None:
    root = ET.parse(path).getroot()
    for node in root.iter("source_ip"):
        assert ipaddress.ip_address(node.text.strip()) in TEST_NET_1, node.text
    for tag in ("domain", "header_from", "envelope_from"):
        for node in root.iter(tag):
            assert node.text.strip().endswith(".test"), node.text
    for address in re.findall(r"[\w.+-]+@([\w.-]+)", path.read_text(encoding="utf-8")):
        assert address.endswith(".test"), address
