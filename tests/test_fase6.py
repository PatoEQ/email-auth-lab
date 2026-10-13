"""Fase 6: límites. Escenario 4, A5 (dominio parecido), A6 (nombre visible) y `lab explicar`."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator

import pytest
from lab import escenarios, explicador, mailpit
from lab.envios import launch_attack, send_legit


def lab(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "COLUMNS": "200"}  # sin cortes de línea de rich
    return subprocess.run(["lab", *args], capture_output=True, text=True, timeout=180, env=env)


def delivered(attack: dict) -> tuple[dict, str]:
    message = mailpit.wait_for_message_id(attack["message_id"], mailpit.queue_id(attack["reply"]))
    assert message, f"{attack['attack']} no llegó a Mailpit"
    return message, mailpit.headers(message["ID"])["Authentication-Results"][0]


@pytest.fixture(scope="module", autouse=True)
def reject_scenario() -> Iterator[None]:
    escenarios.activate("3-reject")
    yield
    escenarios.activate("0")


# --- A5 y A6 en 3-reject (la protección máxima no los detiene) ----------------------


def test_a5_dominio_parecido_pasa_todo_en_reject() -> None:
    attack = launch_attack("A5")
    assert attack["accepted"], attack["reply"]
    message, auth = delivered(attack)
    assert message["From"]["Address"] == "director@bancos3guro.test"
    assert not message["Subject"].startswith("[CUARENTENA]")
    assert "spf=pass" in auth and "smtp.mailfrom=director@bancos3guro.test" in auth
    assert "dkim=pass header.d=bancos3guro.test header.s=p2026" in auth
    assert "dmarc=pass" in auth and "header.from=bancos3guro.test" in auth


def test_a6_nombre_visible_pasa_en_reject() -> None:
    attack = launch_attack("A6")
    assert attack["accepted"], attack["reply"]
    message, auth = delivered(attack)
    assert message["From"] == {"Name": "Director General", "Address": "urgente@atacante.test"}
    assert not message["Subject"].startswith("[CUARENTENA]")
    assert "dkim=pass header.d=atacante.test" in auth
    assert "dmarc=none" in auth, "atacante.test no publica DMARC: no hay nada que aplicar"


def test_a1_a4_siguen_rechazados_en_el_escenario_4() -> None:
    escenarios.activate("4")
    send_legit()
    for attack_id in ("A1", "A2", "A3", "A4"):
        assert launch_attack(attack_id)["code"] == 554, attack_id
    escenarios.activate("3-reject")


# --- detección de engaños (sin red) ----------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("bancos3guro.test", "bancoseguro.test"),
        ("bancoseguros.test", "bancoseguro.test"),
        ("barncoseguro.test", "bancoseguro.test"),
        ("bancoseguro.test", None),
        ("mail.bancoseguro.test", None),
        ("atacante.test", None),
    ],
)
def test_detecta_dominios_parecidos(domain: str, expected: str | None) -> None:
    assert explicador.lookalike_of(domain) == expected


def test_lee_authentication_results_de_rspamd() -> None:
    header = (
        'receptor.bancoseguro.test; dkim=fail ("body hash did not verify") '
        'header.d=bancoseguro.test header.s=s2026 header.b="FKeJKNs/"; '
        'dmarc=fail reason="No valid SPF" header.from=bancoseguro.test (policy=reject); '
        "spf=fail (receptor.bancoseguro.test: domain of director@bancoseguro.test does not "
        "designate 172.28.0.66 as permitted sender) smtp.mailfrom=director@bancoseguro.test"
    )
    results = {r.method: r for r in explicador.parse_auth_results(header)}
    assert results["dkim"].result == "fail"
    assert results["dkim"].props["header.d"] == "bancoseguro.test"
    assert "body hash did not verify" in results["dkim"].comment
    assert results["dmarc"].props["policy"] == "reject"
    assert results["dmarc"].props["reason"] == "No valid SPF"
    assert results["spf"].props["smtp.mailfrom"] == "director@bancoseguro.test"


# --- lab explicar ultimo ---------------------------------------------------------------


def explain_after(sender: str) -> str:
    if sender == "legit":
        assert mailpit.wait_for_message_id(send_legit().message_id)
    else:
        delivered(launch_attack(sender))
    proc = lab("explicar", "ultimo")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return " ".join(proc.stdout.split())


def test_explicar_legitimo() -> None:
    text = explain_after("legit")
    assert "172.28.0.10 — emisor de bancoseguro.test" in text
    assert text.count("✓ coincide") == 2
    assert "El remitente visible es auténtico" in text


def test_explicar_a3_modificado() -> None:
    escenarios.activate("2")
    send_legit()
    text = explain_after("A3")
    escenarios.activate("3-reject")
    assert "172.28.0.66 — atacante" in text
    assert "body hash did not verify" in text
    assert "el correo cambió después de firmarse" in text


def test_explicar_a5_dominio_parecido() -> None:
    text = explain_after("A5")
    assert "Dominio parecido: bancos3guro.test imita a bancoseguro.test" in text
    assert "El remitente visible es auténtico" not in text


def test_explicar_a6_nombre_visible() -> None:
    text = explain_after("A6")
    assert "Nombre visible: dice «Director General»" in text
    assert "urgente@atacante.test" in text
    assert "NONE DMARC" in text


def test_explicar_bandeja_vacia() -> None:
    mailpit.delete_all()
    proc = lab("explicar", "ultimo")
    assert proc.returncode == 1
    assert "La bandeja está vacía" in proc.stdout


def test_atacar_varios_a_la_vez() -> None:
    proc = lab("atacar", "A5", "A6")
    text = " ".join(proc.stdout.split())
    assert "A5 · Dominio parecido" in text and "A6 · Solo el nombre visible" in text
    assert "bancos3guro.test imita a bancoseguro.test" in text
    assert "el nombre visible «Director General» no se verifica" in text
