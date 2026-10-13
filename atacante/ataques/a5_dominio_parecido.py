"""A5 — Dominio parecido: el atacante registra bancos3guro.test (una «e» cambiada por un «3»)
y lo configura impecable: SPF, DKIM (p2026) y DMARC p=reject. Todo pasa, porque el correo
viene de verdad de bancos3guro.test. El engaño está en que el empleado lea «bancoseguro».

Uso dentro del contenedor:  python3 -m ataques.a5_dominio_parecido [--para X] [--servidor Y]
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
    id="A5",
    description="Dominio parecido",
    envelope_from="director@bancos3guro.test",
    header_from="director@bancos3guro.test",
    dkim="d=bancos3guro.test (selector p2026)",
)


def launch(recipient: str = DEFAULT_RECIPIENT, server: str = ALLOWED_SERVER) -> AttackResult:
    return send_simple(ATTACK, recipient, server, sign_with=("bancos3guro.test", "p2026"))


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
