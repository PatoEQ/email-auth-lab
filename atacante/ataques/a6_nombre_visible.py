"""A6 — Solo el nombre visible: From: "Director General" <urgente@atacante.test>.
Muchos clientes de correo (sobre todo en el móvil) muestran solo el nombre, no la dirección.
El correo es auténtico de atacante.test: no suplanta ningún dominio, así que SPF, DKIM y
DMARC no tienen nada que objetar.

Uso dentro del contenedor:  python3 -m ataques.a6_nombre_visible [--para X] [--servidor Y]
"""

from __future__ import annotations

import argparse
import sys

from ataques.comun import (
    ALLOWED_SERVER,
    DEFAULT_RECIPIENT,
    Attack,
    AttackResult,
    DestinationError,
    send_simple,
)

ATTACK = Attack(
    id="A6",
    description="Solo el nombre visible",
    envelope_from="urgente@atacante.test",
    header_from='"Director General" <urgente@atacante.test>',
    dkim="d=atacante.test (selector a2026)",
)


def launch(recipient: str = DEFAULT_RECIPIENT, server: str = ALLOWED_SERVER) -> AttackResult:
    return send_simple(ATTACK, recipient, server, sign_with=("atacante.test", "a2026"))


def main() -> int:
    parser = argparse.ArgumentParser(description=f"{ATTACK.id}: {ATTACK.description}")
    parser.add_argument("--para", default=DEFAULT_RECIPIENT, help="destinatario (.test)")
    parser.add_argument("--servidor", default=ALLOWED_SERVER, help="servidor SMTP (receptor)")
    args = parser.parse_args()
    try:
        result = launch(args.para, args.servidor)
    except DestinationError as error:
        print(f"ABORTADO: {error}", file=sys.stderr)
        return 2
    print(result.transcript)
    return 0 if result.accepted else 1


if __name__ == "__main__":
    sys.exit(main())
