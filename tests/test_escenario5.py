"""Escenario 5 (opcional): dominio que no envía correo y reenvío (perfil `extras`)."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator

import pytest
from lab import dns, escenarios, mailpit, servicios
from lab.envios import forward, launch_attack, list_attacks, send_legit

needs_forwarder = pytest.mark.skipif(
    servicios.reenviador() is None,
    reason="reenviador apagado: docker compose --profile extras up -d --build",
)


def lab(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "COLUMNS": "200"}
    return subprocess.run(["lab", *args], capture_output=True, text=True, timeout=180, env=env)


def delivered(result: dict) -> tuple[dict, str]:
    message = mailpit.wait_for_message_id(result["message_id"], mailpit.queue_id(result["reply"]))
    assert message, "no llegó a Mailpit"
    return message, mailpit.headers(message["ID"])["Authentication-Results"][0]


@pytest.fixture(scope="module", autouse=True)
def scenario_5() -> Iterator[None]:
    escenarios.activate("5")
    assert mailpit.wait_for_message_id(send_legit().message_id), "falta un legítimo firmado"
    yield
    escenarios.activate("0")


# --- dominio que no envía correo -----------------------------------------------------


def test_noenvia_publica_spf_menos_all_y_reject() -> None:
    assert dns.dig("noenvia.test", "TXT") == ["v=spf1 -all"]
    assert dns.dig("_dmarc.noenvia.test", "TXT") == ["v=DMARC1; p=reject"]


def test_n1_rechazado_en_5_y_entregado_en_4() -> None:
    assert launch_attack("N1")["code"] == 554

    escenarios.activate("4")
    assert dns.dig("noenvia.test", "TXT") == [], "en el escenario 4 noenvia.test no publica nada"
    result = launch_attack("N1")
    assert result["accepted"]
    _, auth = delivered(result)
    assert "spf=none" in auth and "dmarc=none" in auth
    escenarios.activate("5")


def test_todos_no_incluye_extras() -> None:
    extras = [a["id"] for a in list_attacks() if a.get("extra")]
    assert extras == ["N1"]
    proc = lab("atacar", "--todos")
    assert "N1 ·" not in proc.stdout


# --- reenvío ------------------------------------------------------------------------


@needs_forwarder
def test_reenvio_tal_cual_dkim_rescata_dmarc() -> None:
    result = forward("tal-cual")
    assert result["accepted"], result["reply"]
    message, auth = delivered(result)
    assert "spf=fail" in auth and "172.28.0.40" in auth, "SPF falla: la IP es del reenviador"
    assert "dkim=pass header.d=bancoseguro.test" in auth
    assert "dmarc=pass" in auth
    assert not message["Subject"].startswith("[CUARENTENA]")


@needs_forwarder
def test_lista_de_correo_rompe_dkim_y_es_rechazada() -> None:
    result = forward("lista")
    assert result["code"] == 554
    assert "DMARC" in result["reply"]


@needs_forwarder
def test_lista_de_correo_en_none_muestra_por_que() -> None:
    escenarios.activate("3-none")
    result = forward("lista")
    assert result["accepted"]
    message, auth = delivered(result)
    escenarios.activate("5")
    assert message["Subject"].startswith("[Asociacion Bancaria]")
    assert "dkim=fail" in auth and "dmarc=fail" in auth


@needs_forwarder
def test_cli_reenviar_y_explicar() -> None:
    proc = lab("reenviar")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "dmarc=pass" in proc.stdout
    text = " ".join(lab("explicar", "ultimo").stdout.split())
    assert "172.28.0.40 — reenviador" in text
    assert "El remitente visible es auténtico" in text
