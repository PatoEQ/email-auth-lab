"""Fase 4: DKIM. Escenario 2, firma del emisor según el escenario, ataques A3 y A4."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator

import pytest
from lab import dns, escenarios, mailpit
from lab.envios import LabError, launch_attack, send_legit


def lab(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["lab", *args], capture_output=True, text=True, timeout=120)


def header(headers: dict[str, list[str]], name: str) -> list[str]:
    """Mailpit normaliza las mayúsculas de los nombres: búsqueda sin distinguirlas."""
    return next((v for k, v in headers.items() if k.lower() == name.lower()), [])


def delivered(message_id: str, reply: str | None = None) -> tuple[dict[str, list[str]], bytes]:
    queue = mailpit.queue_id(reply) if reply else None
    message = mailpit.wait_for_message_id(message_id, queue)
    assert message, "el correo no llegó a Mailpit"
    return mailpit.headers(message["ID"]), mailpit.raw(message["ID"])


def dkim_tags(signature: str) -> dict[str, str]:
    compact = re.sub(r"\s+", "", signature)
    return dict(tag.split("=", 1) for tag in compact.split(";") if "=" in tag)


@pytest.fixture(scope="module", autouse=True)
def restore_scenario_0() -> Iterator[None]:
    yield
    escenarios.activate("0")


def test_escenario_2_publica_spf_y_dkim() -> None:
    result = escenarios.activate("2")
    assert result.propagated
    assert result.emisor_confirmed
    records = {kind: values for kind, _, values in escenarios.published_records()}
    assert records["SPF"] == ["v=spf1 ip4:172.28.0.10 -all"]
    (key,) = records["DKIM"]
    assert key.startswith("v=DKIM1;") and len(key.split("p=", 1)[1]) > 380
    assert records["DMARC"] == []


@pytest.mark.parametrize(("scenario", "signs"), [("1", False), ("2", True)])
def test_emisor_firma_solo_desde_el_escenario_2(scenario: str, signs: bool) -> None:
    result = escenarios.activate(scenario)
    assert result.emisor_confirmed, "el emisor no confirmó el escenario"
    assert escenarios.emisor_state()["firma_dkim"] is signs

    headers, _ = delivered(send_legit().message_id)
    signatures = header(headers, "DKIM-Signature")
    if not signs:
        assert signatures == []
        return
    (signature,) = signatures
    tags = dkim_tags(signature)
    assert tags["d"] == "bancoseguro.test"
    assert tags["s"] == "s2026"
    assert tags["a"] == "rsa-sha256"
    signed = tags["h"].lower().split(":")
    assert signed.count("from") == 2, "el From: debe ir sobrefirmado"
    for name in ("to", "subject", "date", "message-id"):
        assert name in signed, f"la firma no cubre {name}"
    assert "dkim=pass header.d=bancoseguro.test" in header(headers, "Authentication-Results")[0]


def test_a3_cambia_solo_el_cuerpo_y_rompe_la_firma() -> None:
    escenarios.activate("2")
    legit = send_legit()
    original_headers, original_raw = delivered(legit.message_id)

    attack = launch_attack("A3")
    assert attack["accepted"], attack["reply"]
    assert attack["message_id"] == legit.message_id, "A3 reenvía el correo tal cual"
    headers, raw = delivered(attack["message_id"], attack["reply"])

    assert header(headers, "DKIM-Signature") == header(original_headers, "DKIM-Signature")
    assert b"0012-3456-78" in original_raw and b"0012-3456-78" not in raw
    assert b"9999-6666-00" in raw
    auth = header(headers, "Authentication-Results")[0]
    assert "dkim=fail" in auth and "body hash did not verify" in auth, auth
    assert "header.d=bancoseguro.test" in auth


def test_a3_sin_correo_legitimo_explica_que_hacer() -> None:
    mailpit.delete_all()
    with pytest.raises(LabError, match="lab.sh enviar legit"):
        launch_attack("A3")


def test_a4_firma_valida_de_otro_dominio() -> None:
    escenarios.activate("2")
    attack = launch_attack("A4")
    headers, _ = delivered(attack["message_id"], attack["reply"])
    assert header(headers, "From") == ["director@bancoseguro.test"]
    tags = dkim_tags(header(headers, "DKIM-Signature")[0])
    assert (tags["d"], tags["s"]) == ("atacante.test", "a2026")
    auth = header(headers, "Authentication-Results")[0]
    assert "dkim=pass header.d=atacante.test header.s=a2026" in auth, auth


def test_llave_del_atacante_publicada() -> None:
    (key,) = dns.dig("a2026._domainkey.atacante.test", "TXT")
    assert key.startswith("v=DKIM1;")


def test_cli_escenario_2_confirma_el_emisor() -> None:
    escenarios.activate("1")
    proc = lab("escenario", "2")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "(confirmado por el emisor)" in proc.stdout
    assert "+ s2026._domainkey IN TXT" in proc.stdout


def test_cli_atacar_a3_explica_la_modificacion() -> None:
    escenarios.activate("2")
    send_legit()
    proc = lab("atacar", "A3")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    text = " ".join(proc.stdout.split())
    assert "dkim=fail" in text
    assert "El correo fue modificado" in text


def test_cli_atacar_a4_explica_quien_firmo() -> None:
    escenarios.activate("2")
    proc = lab("atacar", "A4")
    text = " ".join(proc.stdout.split())
    assert "firmado por atacante.test, no por bancoseguro.test" in text
