"""Genera las capturas SVG de la documentación con la salida real de la CLI.

Uso (desde la raíz del repo):
  docker compose run --rm -v ./docs/img:/salida toolbox python -m lab.capturas /salida

Cambia escenarios y vacía Mailpit: úsalo con el laboratorio en reposo.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from lab import cli, escenarios, mailpit

WIDTH = 100


def capture(path: Path, title: str, steps: list[tuple[str, Callable[[], None]]]) -> None:
    cli.console = Console(record=True, width=WIDTH, force_terminal=True, highlight=False)
    for prompt, action in steps:
        cli.console.print(f"[bold]$ ./lab.sh {prompt}[/]")
        action()
        cli.console.print()
    cli.console.save_svg(str(path), title=title)
    # El contenedor corre como root: el archivo queda del dueño de la carpeta de salida.
    owner = path.parent.stat()
    os.chown(path, owner.st_uid, owner.st_gid)
    print(f"[capturas] {path}")


def run(*argv: str) -> Callable[[], None]:
    return lambda: cli.main(list(argv))


def main(output: str) -> int:
    out = Path(output)
    mailpit.delete_all()
    escenarios.activate("0")
    capture(
        out / "escenario-0-ataque-a1.svg",
        "Escenario 0: la suplantación llega",
        [("atacar A1", run("atacar", "A1"))],
    )
    escenarios.activate("3-reject")
    capture(
        out / "escenario-3-reject-todos.svg",
        "Escenario 3-reject: A1–A4 rechazados",
        [("enviar legit", run("enviar", "legit")), ("atacar --todos", run("atacar", "--todos"))],
    )
    escenarios.activate("4")
    capture(
        out / "escenario-4-explicar-a5.svg",
        "Escenario 4: dominio parecido",
        [("atacar A5", run("atacar", "A5")), ("explicar ultimo", run("explicar", "ultimo"))],
    )
    capture(out / "reportes.svg", "Reporte DMARC agregado", [("reportes", run("reportes"))])
    escenarios.activate("0")
    mailpit.delete_all()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/salida"))
