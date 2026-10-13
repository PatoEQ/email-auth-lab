"""Consultas DNS con dig contra el servidor del laboratorio."""

from __future__ import annotations

import subprocess

from lab.config import DNS_SERVER


def dig(name: str, rtype: str) -> list[str]:
    """Respuestas de `dig +short`. Une los TXT partidos en varias cadenas."""
    proc = subprocess.run(
        ["dig", "+short", "+time=2", "+tries=2", f"@{DNS_SERVER}", name, rtype],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"dig falló ({proc.returncode}): {proc.stderr.strip()}")
    answers = [line for line in proc.stdout.splitlines() if line.strip()]
    if rtype.upper() == "TXT":
        answers = ["".join(part.strip('"') for part in a.split('" "')) for a in answers]
    return answers


def soa_serial(zone: str) -> int | None:
    answers = dig(zone, "SOA")
    return int(answers[0].split()[2]) if answers else None
