"""CLI `lab`: maneja el laboratorio desde la toolbox (ver CLAUDE.md, sección 7)."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lab import escenarios, mailpit, servicios
from lab.config import ZONE_TTL
from lab.envios import LabError, launch_attack, list_attacks, send_legit

console = Console(highlight=False)


def _auth_results(message_id: str) -> tuple[bool, str]:
    """¿Llegó a Mailpit? y su Authentication-Results (si llegó)."""
    message = mailpit.wait_for_message_id(message_id, timeout=15)
    if not message:
        return False, ""
    values = mailpit.headers(message["ID"]).get("Authentication-Results", [])
    return True, values[0] if values else "(sin cabecera Authentication-Results)"


def _verdicts(auth_results: str) -> str:
    """Extrae «spf=… dkim=… dmarc=…» de Authentication-Results para mostrarlo corto."""
    parts = []
    for method in ("spf", "dkim", "dmarc"):
        for token in auth_results.replace(";", " ").split():
            if token.startswith(f"{method}="):
                parts.append(token)
                break
    return "  ".join(parts) or auth_results


def _domain(address: str) -> str:
    return address.rpartition("@")[2].strip('<>" ').lower()


def _interpret(auth: str, envelope_from: str, header_from: str) -> str:
    """Qué significa el resultado de SPF para la persona que lee el correo."""
    envelope, visible = _domain(envelope_from), _domain(header_from)
    if "spf=pass" in auth and envelope != visible:
        return (
            f"SPF pasó, pero para [bold]{envelope}[/] (el sobre), no para [bold]{visible}[/], "
            "que es lo que ve el empleado. SPF no compara esos dos dominios."
        )
    if "spf=pass" in auth:
        return f"SPF pasó: la IP de origen está autorizada por {envelope}."
    if "spf=fail" in auth:
        return (
            f"SPF falló: {envelope} no autoriza esa IP. Pero nadie le dijo al receptor qué "
            "hacer con un fallo (eso es DMARC), así que lo entregó igual."
        )
    if "spf=none" in auth:
        return f"{envelope} no publica SPF: no hay nada que verificar."
    return ""


def _show_delivery(
    message_id: str, smtp_accepted: bool, envelope_from: str, header_from: str
) -> None:
    if not smtp_accepted:
        return
    delivered, auth = _auth_results(message_id)
    if delivered:
        console.print(f"  [green]Llegó a la bandeja del empleado[/] (Mailpit).  {_verdicts(auth)}")
        meaning = _interpret(auth, envelope_from, header_from)
        if meaning:
            console.print(f"  [bold]Qué significa:[/] {meaning}")
    else:
        console.print("  [yellow]Todavía no aparece en Mailpit.[/] Revisa en unos segundos.")


# --- comandos ---------------------------------------------------------------


def cmd_escenario(args: argparse.Namespace) -> int:
    try:
        result = escenarios.activate(args.id)
    except ValueError as error:
        console.print(f"[red]✗ {error}[/]")
        return 2

    state = result.state
    console.print(
        Panel.fit(
            f"[bold]Escenario {state['escenario']}: {state['nombre']}[/]",
            border_style="cyan",
        )
    )
    if result.previous == state["escenario"]:
        console.print("Ya estaba activo; se volvió a publicar la zona (serial nuevo).")
    elif result.added or result.removed:
        console.print(f"Cambios en la zona DNS respecto al escenario {result.previous}:")
        for line in result.removed:
            console.print(f"  [red]- {line}[/]")
        for line in result.added:
            console.print(f"  [green]+ {line}[/]")
    else:
        console.print("La zona DNS de bancoseguro.test no cambió respecto al escenario anterior.")

    if result.waited_ttl:
        console.print(
            f"[dim]Esperé {ZONE_TTL} s (el TTL de la zona) para que el receptor no use "
            "registros viejos de su caché.[/]"
        )
    if not result.propagated:
        console.print("[yellow]⚠ El DNS todavía no sirve el serial nuevo. Revisa `lab estado`.[/]")
    console.print(f"Serial SOA publicado: {state['serial']}")
    firma = "[green]activada[/]" if state["firma_dkim"] else "[yellow]desactivada[/]"
    console.print(f"Firma DKIM del emisor: {firma}")
    _print_records()
    console.print(f"\n[bold]Qué significa:[/] {escenarios.MEANING.get(state['escenario'], '')}")
    return 0


def _print_records() -> None:
    table = Table(title="Registros publicados en el DNS", title_justify="left")
    table.add_column("Tipo")
    table.add_column("Nombre")
    table.add_column("Valor")
    for kind, name, values in escenarios.published_records():
        shown = "\n".join(v if len(v) < 90 else v[:87] + "…" for v in values)
        table.add_row(kind, name, shown or "[dim](no publicado)[/]")
    console.print(table)


def cmd_enviar(args: argparse.Namespace) -> int:
    try:
        result = send_legit()
    except LabError as error:
        console.print(f"[red]✗ {error}[/]")
        return 1
    console.print(f"[bold]Correo legítimo[/] de {result.header_from} → empleado@bancoseguro.test")
    if result.accepted:
        console.print(f"  Emisor: [green]{result.code}[/] {result.reply}")
        console.print("  El servidor del banco lo aceptó y lo entrega al MX (receptor).")
    else:
        console.print(f"  Emisor: [red]{result.code}[/] {result.reply}")
    _show_delivery(result.message_id, result.accepted, result.envelope_from, result.header_from)
    return 0 if result.accepted else 1


def _explain_smtp(result: dict[str, Any]) -> str:
    code = result["code"]
    if 200 <= code < 300:
        return "[green]ACEPTADO[/]: el receptor recibió el correo para entregarlo."
    if 500 <= code < 600:
        return "[red]RECHAZADO[/]: el receptor lo bloqueó en la conversación SMTP."
    if 400 <= code < 500:
        return "[yellow]RECHAZO TEMPORAL[/]: el receptor pide reintentar más tarde."
    return "[yellow]Sin respuesta clara del receptor.[/]"


def cmd_atacar(args: argparse.Namespace) -> int:
    try:
        catalog = {a["id"]: a for a in list_attacks()}
        if args.todos:
            ids = list(catalog)
        elif args.id:
            ids = [args.id.upper()]
        else:
            console.print("[red]✗ Indica un ataque (por ejemplo, A1) o usa --todos.[/]")
            return 2
        unknown = [i for i in ids if i not in catalog]
        if unknown:
            console.print(
                f"[red]✗ El ataque {', '.join(unknown)} no está disponible todavía.[/] "
                f"Disponibles: {', '.join(catalog)}"
            )
            return 2

        for attack_id in ids:
            attack = catalog[attack_id]
            result = launch_attack(attack_id, args.para)
            console.print(f"\n[bold]{attack_id} · {attack['description']}[/]")
            console.print(f"  Sobre (MAIL FROM): {result['envelope_from']}")
            console.print(f"  Remitente visible (From:): {result['header_from']}")
            console.print(f"  Firma DKIM: {attack['dkim']}")
            console.print(f"  Respuesta SMTP: {result['code']} {result['reply']}")
            console.print(f"  {_explain_smtp(result)}")
            _show_delivery(
                result["message_id"],
                result["accepted"],
                result["envelope_from"],
                result["header_from"],
            )
    except LabError as error:
        console.print(f"[red]✗ {error}[/]")
        return 2
    return 0


def cmd_estado(args: argparse.Namespace) -> int:
    state = escenarios.current_state()
    if state:
        console.print(
            f"[bold]Escenario activo:[/] {state['escenario']} · {state['nombre']}  "
            f"[dim](serial {state['serial']}, desde {state['activado']})[/]"
        )
    else:
        console.print("[yellow]No hay escenario activo: ¿corrió el servicio init?[/]")

    table = Table(title="Servicios", title_justify="left")
    table.add_column("Servicio")
    table.add_column("Función")
    table.add_column("Estado")
    table.add_column("Detalle")
    all_ok = True
    for name, role, ok, detail in servicios.check_all():
        all_ok &= ok
        table.add_row(name, role, "[green]✓ ok[/]" if ok else "[red]✗ falla[/]", detail)
    console.print(table)

    if all_ok:
        _print_records()
        console.print("[green]Todo listo.[/] El laboratorio responde y puede usarse.")
    else:
        console.print(
            "[red]Hay servicios que no responden.[/] Prueba `docker compose ps` y "
            "`docker compose logs <servicio>`."
        )
    return 0 if all_ok else 1


def cmd_reset(args: argparse.Namespace) -> int:
    try:
        mailpit.delete_all()
    except OSError as error:
        console.print(f"[red]✗ No pude vaciar Mailpit: {error}[/]")
        return 1
    console.print("[green]✓[/] Bandeja de Mailpit vacía.")
    result = escenarios.activate("0")
    console.print(f"[green]✓[/] Escenario 0 activo (serial {result.state['serial']}).")
    console.print("El laboratorio vuelve al punto de partida: sin SPF, DKIM ni DMARC.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab", description="Laboratorio de SPF, DKIM y DMARC (dominios .test, red aislada)."
    )
    sub = parser.add_subparsers(dest="comando", required=True, metavar="<comando>")

    p = sub.add_parser("escenario", help="activa un escenario (zona DNS y firma DKIM)")
    p.add_argument("id", help=f"escenario: {', '.join(escenarios.ESCENARIOS)}")
    p.set_defaults(func=cmd_escenario)

    p = sub.add_parser("enviar", help="envía el correo legítimo desde el emisor")
    p.add_argument("tipo", choices=["legit"], help="tipo de correo (legit)")
    p.set_defaults(func=cmd_enviar)

    p = sub.add_parser("atacar", help="lanza ataques desde el contenedor atacante")
    p.add_argument("id", nargs="?", help="ataque: A1…A6")
    p.add_argument("--todos", action="store_true", help="lanza todos los ataques disponibles")
    p.add_argument("--para", help=argparse.SUPPRESS)  # solo para demostrar la validación
    p.set_defaults(func=cmd_atacar)

    p = sub.add_parser("estado", help="escenario activo y salud de los servicios")
    p.set_defaults(func=cmd_estado)

    p = sub.add_parser("reset", help="vacía Mailpit y vuelve al escenario 0")
    p.set_defaults(func=cmd_reset)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
