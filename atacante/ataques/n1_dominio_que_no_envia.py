"""N1 — Dominio que no envía (escenario 5, extra): el atacante usa facturas@noenvia.test,
un dominio de la organización que nunca envía correo. Si ese dominio no publica nada,
el correo llega; con «v=spf1 -all» y DMARC p=reject, se rechaza.

Uso dentro del contenedor:  python3 -m ataques.n1_dominio_que_no_envia [--para X]
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
    id="N1",
    description="Dominio que no envía correo",
    envelope_from="facturas@noenvia.test",
    header_from="facturas@noenvia.test",
    dkim="ninguna",
    extra=True,
)


def launch(recipient: str = DEFAULT_RECIPIENT, server: str = ALLOWED_SERVER) -> AttackResult:
    return send_simple(ATTACK, recipient, server)


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
