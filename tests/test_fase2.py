"""Fase 2: escenario 0, init, atacante, CLI `lab` y cambio de escenario sin docker.sock."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from lab import dns, escenarios, mailpit
from lab.envios import LabError, launch_attack, send_legit

ESTADO = Path("/estado/estado.json")


def lab(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["lab", *args], capture_output=True, text=True, timeout=120)


def auth_results(message_id: str) -> str:
    message = mailpit.wait_for_message_id(message_id)
    assert message, "el correo no llegó a Mailpit"
    return mailpit.headers(message["ID"])["Authentication-Results"][0]


# --- init y DNS ---------------------------------------------------------------


def test_init_publica_dkim_del_atacante_completo() -> None:
    """La llave de 2048 bits se publica entera (partida en cadenas de ≤255)."""
    for name in ("a2026._domainkey.atacante.test", "p2026._domainkey.bancos3guro.test"):
        (record,) = dns.dig(name, "TXT")
        assert record.startswith("v=DKIM1;")
        assert len(record.split("p=", 1)[1]) > 380, "llave pública incompleta"


def test_escenario_0_no_publica_autenticacion() -> None:
    escenarios.activate("0")
    for kind, name, values in escenarios.published_records():
        assert values == [], f"{kind} en {name} no debería existir en el escenario 0"


def test_cambio_de_escenario_por_volumen_compartido() -> None:
    """La toolbox escribe estado/ y zonas; CoreDNS recoge el serial nuevo solo."""
    before = dns.soa_serial("bancoseguro.test")
    result = escenarios.activate("0")
    assert result.propagated
    assert result.state["serial"] > before
    assert dns.soa_serial("bancoseguro.test") == result.state["serial"]

    state = json.loads(ESTADO.read_text(encoding="utf-8"))
    assert state["escenario"] == "0"
    assert state["firma_dkim"] is False


def test_sin_docker_sock() -> None:
    assert not Path("/var/run/docker.sock").exists()


# --- atacante -------------------------------------------------------------------


def test_a1_sale_desde_la_ip_del_atacante() -> None:
    result = launch_attack("A1")
    assert result["accepted"], result["reply"]
    auth = auth_results(result["message_id"])
    assert "when checking 172.28.0.66" in auth, auth
    assert "smtp.mailfrom=director@bancoseguro.test" in auth


@pytest.mark.parametrize("recipient", ["alguien@gmail.com", "empleado@bancoseguro.com", "x"])
def test_atacante_rechaza_destinos_fuera_de_test(recipient: str) -> None:
    with pytest.raises(LabError, match="solo envía correo a dominios .test"):
        launch_attack("A1", recipient)


# --- emisor ---------------------------------------------------------------------


def test_legitimo_viaja_emisor_receptor_mailpit() -> None:
    result = send_legit()
    assert result.accepted, result.reply
    auth = auth_results(result.message_id)
    assert "when checking 172.28.0.10" in auth, "no salió del emisor"


# --- CLI ------------------------------------------------------------------------


def test_cli_estado_todo_ok() -> None:
    proc = lab("estado")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Escenario activo: 0" in proc.stdout
    assert "falla" not in proc.stdout


def test_cli_escenario_inexistente() -> None:
    proc = lab("escenario", "9")
    assert proc.returncode == 2
    assert "no existe" in proc.stdout


def test_cli_atacar_a1() -> None:
    proc = lab("atacar", "A1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ACEPTADO" in proc.stdout
    assert "Llegó a la bandeja" in proc.stdout


def test_cli_ataque_no_disponible() -> None:
    proc = lab("atacar", "A9")
    assert proc.returncode == 2
    assert "no está disponible" in proc.stdout


def test_cli_reset_vacia_mailpit_y_vuelve_a_0() -> None:
    # Espera a que llegue: si no, podría entrar a Mailpit después del reset.
    auth_results(launch_attack("A1")["message_id"])
    proc = lab("reset")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert mailpit.info()["Messages"] == 0
    assert escenarios.current_state()["escenario"] == "0"
