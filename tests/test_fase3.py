"""Fase 3: SPF. Escenario 1, ataque A2 y el cambio de escenario en vivo."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator

import pytest
from lab import dns, escenarios, mailpit
from lab.envios import launch_attack

SPF_BANCO = "v=spf1 ip4:172.28.0.10 -all"


def lab(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["lab", *args], capture_output=True, text=True, timeout=120)


def spf_records(domain: str) -> list[str]:
    return [r for r in dns.dig(domain, "TXT") if r.startswith("v=spf1")]


def auth_results(message_id: str) -> str:
    message = mailpit.wait_for_message_id(message_id)
    assert message, "el correo no llegó a Mailpit"
    return mailpit.headers(message["ID"])["Authentication-Results"][0]


@pytest.fixture(scope="module", autouse=True)
def restore_scenario_0() -> Iterator[None]:
    yield
    escenarios.activate("0")


def test_escenario_1_publica_solo_spf() -> None:
    assert escenarios.activate("1").propagated
    records = {kind: values for kind, _, values in escenarios.published_records()}
    assert records == {"SPF": [SPF_BANCO], "DKIM": [], "DMARC": []}
    assert escenarios.current_state()["firma_dkim"] is False


def test_spf_del_atacante_en_todos_los_escenarios() -> None:
    for scenario in ("0", "1"):
        escenarios.activate(scenario)
        assert spf_records("atacante.test") == ["v=spf1 ip4:172.28.0.66 -all"]
        assert dns.dig("_dmarc.atacante.test", "TXT") == [], "atacante.test no publica DMARC"


def test_cambio_de_escenario_se_nota_en_el_siguiente_correo() -> None:
    """Ida y vuelta 0 → 1 → 0: el receptor no debe usar un SPF viejo de su caché."""
    for scenario, want in (("0", "spf=none"), ("1", "spf=fail"), ("0", "spf=none")):
        escenarios.activate(scenario)
        auth = auth_results(launch_attack("A1")["message_id"])
        assert want in auth, f"escenario {scenario}: se esperaba {want} y llegó «{auth}»"


def test_a2_sobre_del_atacante_from_del_director() -> None:
    escenarios.activate("1")
    result = launch_attack("A2")
    assert result["envelope_from"] == "rebote@atacante.test"
    assert result["header_from"] == "director@bancoseguro.test"
    message = mailpit.wait_for_message_id(result["message_id"])
    assert message
    assert message["From"]["Address"] == "director@bancoseguro.test", "el empleado ve al director"
    headers = mailpit.headers(message["ID"])
    assert headers["Return-Path"] == ["<rebote@atacante.test>"], "el sobre es del atacante"


def test_cli_escenario_1_muestra_el_cambio() -> None:
    escenarios.activate("0")
    proc = lab("escenario", "1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f'+ @ IN TXT "{SPF_BANCO}"' in proc.stdout
    assert "Esperé 5 s" in proc.stdout


def test_cli_atacar_a2_explica_spf_pass() -> None:
    escenarios.activate("1")
    proc = lab("atacar", "A2")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "spf=pass" in proc.stdout
    assert "no para bancoseguro.test" in " ".join(proc.stdout.split())


def test_cli_enviar_legit_spf_pass() -> None:
    escenarios.activate("1")
    proc = lab("enviar", "legit")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "spf=pass" in proc.stdout
