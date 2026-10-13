"""Utilidades compartidas por los tests: envío SMTP y consulta de la API de Mailpit."""

from __future__ import annotations

import json
import smtplib
import time
import uuid
from collections.abc import Iterator
from email.message import EmailMessage
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

import pytest

RECEPTOR = "receptor"
MAILPIT_API = "http://mailpit:8025/api/v1"


def mailpit_get(path: str) -> Any:
    with urlopen(f"{MAILPIT_API}{path}", timeout=5) as resp:
        return json.load(resp)


def mailpit_delete_all() -> None:
    urlopen(Request(f"{MAILPIT_API}/messages", method="DELETE"), timeout=5).close()


def wait_for_message(subject: str, timeout: float = 20.0) -> dict[str, Any]:
    """Espera a que aparezca en Mailpit un correo con ese asunto exacto."""
    deadline = time.monotonic() + timeout
    query = quote(f'subject:"{subject}"')
    while time.monotonic() < deadline:
        found = mailpit_get(f"/search?query={query}")["messages"]
        if found:
            return found[0]
        time.sleep(0.5)
    raise AssertionError(f"El correo «{subject}» no llegó a Mailpit en {timeout:.0f} s")


def build_message(sender: str, recipient: str, subject: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Message-ID"] = f"<{uuid.uuid4()}@lab.test>"
    msg.set_content("Correo de prueba del laboratorio email-auth-lab.\n")
    return msg


@pytest.fixture
def unique_subject() -> str:
    return f"Prueba fase 1 {uuid.uuid4().hex[:8]}"


@pytest.fixture
def smtp() -> Iterator[smtplib.SMTP]:
    with smtplib.SMTP(RECEPTOR, 25, local_hostname="toolbox.lab.test", timeout=30) as conn:
        yield conn
