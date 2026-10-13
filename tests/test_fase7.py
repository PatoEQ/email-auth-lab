"""Fase 7: `lab verificar` (validación de sintaxis de los registros publicados)."""

from __future__ import annotations

import base64
import os
import subprocess
from collections.abc import Iterator

import pytest
from lab import escenarios, verificar

# Llaves "de mentira" con el largo DER de una RSA real: el validador mide el largo,
# no verifica la llave (eso lo hace el receptor al comprobar la firma).
KEY_2048 = base64.b64encode(b"\x30" * 294).decode()
KEY_1024 = base64.b64encode(b"\x30" * 162).decode()


def lab(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "COLUMNS": "200"}
    return subprocess.run(["lab", *args], capture_output=True, text=True, timeout=120, env=env)


def failures(checks: list[verificar.Check]) -> list[str]:
    return [c.message for c in checks if not c.ok and not c.warning]


@pytest.fixture(scope="module", autouse=True)
def restore_scenario_0() -> Iterator[None]:
    yield
    escenarios.activate("0")


# --- validadores (sin red) -------------------------------------------------------------


@pytest.mark.parametrize(
    ("records", "problem"),
    [
        (["v=spf1 ip4:172.28.0.10 -all"], None),
        (["v=spf1 -all"], None),
        (["v=spf1 ip4:172.28.0.10 -all", "v=spf1 -all"], "más de un registro SPF"),
        (["v=spf1 ip4:172.28.0.10 permitir -all"], "Términos inválidos: permitir"),
        (["v=spf1 " + " ".join(f"include:p{i}.test" for i in range(11)) + " -all"], "11 consultas"),
        (["v=spf1 ip4:172.28.0.10"], "No termina en «all»"),
        ([], "No hay registro SPF"),
    ],
)
def test_validar_spf(records: list[str], problem: str | None) -> None:
    errors = failures(verificar.spf(records))
    if problem is None:
        assert errors == []
    else:
        assert any(problem in e for e in errors), errors


def test_spf_tilde_all_es_aviso() -> None:
    checks = verificar.spf(["v=spf1 ip4:172.28.0.10 ~all"])
    assert failures(checks) == []
    assert any(c.warning and "~all" in c.message for c in checks)


@pytest.mark.parametrize(
    ("records", "problem"),
    [
        ([f"v=DKIM1; k=rsa; p={KEY_2048}"], None),
        (["v=DKIM1; k=rsa; p="], "revocada"),
        (["v=DKIM1; k=rsa; p=esto-no-es-base64!"], "base64"),
        ([f"v=DKIM1; k=rsa; p={KEY_1024}"], "1024 bits"),
        ([], "No hay llave"),
    ],
)
def test_validar_dkim(records: list[str], problem: str | None) -> None:
    errors = failures(verificar.dkim(records))
    if problem is None:
        assert errors == []
    else:
        assert any(problem in e for e in errors), errors


@pytest.mark.parametrize(
    ("records", "problem"),
    [
        (["v=DMARC1; p=reject; rua=mailto:dmarc-reportes@bancoseguro.test"], None),
        (["v=DMARC1; rua=mailto:x@bancoseguro.test"], "Falta la etiqueta obligatoria p="),
        (["v=DMARC1; p=bloquear; rua=mailto:x@bancoseguro.test"], "p=bloquear"),
        (["v=DMARC1; p=none; rua=dmarc@bancoseguro.test"], "rua inválido"),
        (["v=DMARC1; p=none; pct=150; rua=mailto:x@b.test"], "pct=150"),
        (["p=reject; v=DMARC1"], "primera etiqueta"),
        ([], "No hay política DMARC"),
    ],
)
def test_validar_dmarc(records: list[str], problem: str | None) -> None:
    errors = failures(verificar.dmarc(records))
    if problem is None:
        assert errors == []
    else:
        assert any(problem in e for e in errors), errors


def test_dmarc_sin_rua_es_aviso() -> None:
    checks = verificar.dmarc(["v=DMARC1; p=reject"])
    assert failures(checks) == []
    assert any(c.warning and "rua" in c.message for c in checks)


# --- lab verificar contra el DNS del laboratorio ------------------------------------


def test_cli_verificar_escenario_0() -> None:
    escenarios.activate("0")
    proc = lab("verificar")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "le falta: SPF, DKIM, DMARC" in " ".join(proc.stdout.split())


def test_cli_verificar_3_reject_todo_valido() -> None:
    escenarios.activate("3-reject")
    proc = lab("verificar")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "✗" not in proc.stdout and "⚠" not in proc.stdout
    assert "Llave RSA de 2048 bits" in proc.stdout
    assert "Política p=reject" in proc.stdout


def test_cli_verificar_escenario_5_incluye_noenvia() -> None:
    escenarios.activate("5")
    proc = lab("verificar")
    assert "dig TXT _dmarc.noenvia.test" in proc.stdout
    assert "⚠ Sin rua=" in proc.stdout
