"""Fase 1: esqueleto. Un correo simple llega del receptor a Mailpit con Authentication-Results."""

from __future__ import annotations

import smtplib
import subprocess

import pytest
from conftest import build_message, mailpit_get, wait_for_message
from lab import escenarios


def dig(name: str, rtype: str) -> list[str]:
    out = subprocess.run(
        ["dig", "+short", "@172.28.0.53", name, rtype],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return out.stdout.split("\n")[:-1]


def test_dns_mx_apunta_al_receptor() -> None:
    assert dig("bancoseguro.test", "MX") == ["10 receptor.bancoseguro.test."]
    assert dig("receptor.bancoseguro.test", "A") == ["172.28.0.25"]


def test_dns_no_resuelve_dominios_reales() -> None:
    assert dig("example.com", "A") == []


def test_correo_simple_llega_a_mailpit(smtp: smtplib.SMTP, unique_subject: str) -> None:
    escenarios.activate("0")
    msg = build_message("prueba@bancoseguro.test", "empleado@bancoseguro.test", unique_subject)
    smtp.send_message(msg)

    found = wait_for_message(unique_subject)
    headers = mailpit_get(f"/message/{found['ID']}/headers")

    auth_results = headers.get("Authentication-Results", [])
    assert auth_results, "Rspamd no agregó la cabecera Authentication-Results"
    # Escenario 0: bancoseguro.test no publica SPF, así que el resultado real es spf=none.
    assert "spf=none" in auth_results[0], auth_results[0]
    assert "smtp.mailfrom=prueba@bancoseguro.test" in auth_results[0], auth_results[0]


def test_receptor_no_es_relay_abierto(smtp: smtplib.SMTP) -> None:
    smtp.ehlo()
    smtp.mail("prueba@bancoseguro.test")
    code, reply = smtp.rcpt("alguien@atacante.test")
    assert code == 554, (code, reply)
    assert b"Relay access denied" in reply


def test_red_lab_sin_salida_a_internet() -> None:
    """lab-net es interna: desde la toolbox no debe haber salida a Internet."""
    with pytest.raises(OSError):
        smtplib.SMTP("1.1.1.1", 25, timeout=3)
