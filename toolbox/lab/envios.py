"""Envío del correo legítimo (vía emisor) y de los ataques (vía API del atacante)."""

from __future__ import annotations

import json
import smtplib
import uuid
from dataclasses import dataclass
from email.message import EmailMessage
from email.policy import SMTP
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from lab.config import ATACANTE_API, DIRECTOR, EMISOR, EMPLOYEE

LEGIT_SUBJECT = "Pago a proveedor: factura 2026-118"
LEGIT_ACCOUNT = "0012-3456-78"
LEGIT_BODY = f"""Hola:

Por favor programa para el viernes el pago de la factura 2026-118 de
Papelería Central, por 1.250 USD, a su cuenta habitual {LEGIT_ACCOUNT}.

Gracias,
Director General
Banco Seguro
"""


@dataclass
class SendResult:
    accepted: bool
    code: int
    reply: str
    message_id: str
    envelope_from: str
    header_from: str


class LabError(RuntimeError):
    """Error con un mensaje en español listo para mostrar."""


def send_legit() -> SendResult:
    """El director envía un correo real desde el servidor del banco (emisor)."""
    msg = EmailMessage(policy=SMTP)
    msg["From"] = f"Director General <{DIRECTOR}>"
    msg["To"] = EMPLOYEE
    msg["Subject"] = LEGIT_SUBJECT
    message_id = f"{uuid.uuid4()}@bancoseguro.test"
    msg["Message-ID"] = f"<{message_id}>"
    msg.set_content(LEGIT_BODY)

    try:
        with smtplib.SMTP(EMISOR, 25, local_hostname="toolbox.bancoseguro.test", timeout=30) as s:
            s.ehlo()
            s.mail(DIRECTOR)
            code, reply = s.rcpt(EMPLOYEE)
            if code < 400:
                code, reply = s.data(msg.as_bytes())
    except OSError as error:
        raise LabError(f"No pude conectar con el emisor: {error}") from error

    return SendResult(
        accepted=200 <= code < 300,
        code=code,
        reply=reply.decode(errors="replace"),
        message_id=message_id,
        envelope_from=DIRECTOR,
        header_from=str(msg["From"]),
    )


def _atacante(path: str, payload: dict[str, str] | None = None) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    request = Request(
        f"{ATACANTE_API}{path}",
        data=data,
        method="POST" if data is not None else "GET",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=90) as resp:
            return json.load(resp)
    except HTTPError as error:
        detail = json.load(error).get("error", str(error))
        raise LabError(detail) from error
    except OSError as error:
        raise LabError(f"No pude conectar con el atacante: {error}") from error


def list_attacks() -> list[dict[str, str]]:
    return _atacante("/ataques")


def launch_attack(attack_id: str, recipient: str | None = None) -> dict[str, Any]:
    payload = {"para": recipient} if recipient else {}
    return _atacante(f"/atacar/{attack_id.upper()}", payload)
