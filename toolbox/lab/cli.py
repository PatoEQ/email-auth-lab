"""CLI `lab`: maneja el laboratorio desde la toolbox (ver CLAUDE.md, sección 7)."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from lab import escenarios, mailpit, reportes, servicios
from lab.config import ZONE_TTL
from lab.envios import LabError, launch_attack, list_attacks, send_legit

console = Console(highlight=False)

QUARANTINE_TAG = "[CUARENTENA]"  # receptor/rspamd/actions.conf


def _auth_results(
    message_id: str, receptor_queue_id: str | None
) -> tuple[dict[str, Any] | None, str]:
    """El correo en Mailpit (si llegó) y su Authentication-Results."""
    message = mailpit.wait_for_message_id(message_id, receptor_queue_id, timeout=15)
    if not message:
        return None, ""
    values = mailpit.headers(message["ID"]).get("Authentication-Results", [])
    return message, values[0] if values else "(sin cabecera Authentication-Results)"


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


def _interpret_spf(auth: str, envelope: str, visible: str) -> str:
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


def _interpret_dkim(auth: str, visible: str) -> str:
    match = re.search(r"dkim=(\w+)(?:[^;]*?header\.d=([\w.-]+))?", auth)
    if not match or match.group(1) == "none":
        return "Sin firma DKIM."
    result, signer = match.group(1), (match.group(2) or "?").lower()
    if result == "pass" and signer != visible:
        return (
            f"DKIM válido, pero firmado por [bold]{signer}[/], no por [bold]{visible}[/]. "
            "Prueba quién firmó, no que el remitente visible sea auténtico."
        )
    if result == "pass":
        return f"DKIM válido: {signer} firmó este correo y nadie lo modificó después."
    if result == "fail":
        return (
            f"DKIM falló: la firma de {signer} no coincide con el contenido. "
            "[bold]El correo fue modificado[/] después de firmarse."
        )
    return f"DKIM no se pudo verificar ({result}) para {signer}."


def _interpret_dmarc(auth: str, visible: str) -> str:
    match = re.search(r"dmarc=(\w+)", auth)
    if not match or match.group(1) == "none":
        return f"{visible} no publica DMARC: no hay política que aplicar."
    policy = re.search(r"policy=(\w+)", auth)
    policy_name = policy.group(1) if policy else "?"
    if match.group(1) == "pass":
        return (
            f"DMARC pasó: SPF o DKIM validan [bold]{visible}[/], el mismo dominio del "
            "From: (alineación)."
        )
    reason = re.search(r'reason="([^"]+)"', auth)
    why = f" ({reason.group(1)})" if reason else ""
    consequence = {
        "none": "La política es p=none (solo observar): se entregó igual.",
        "quarantine": "La política es p=quarantine: se entregó [bold]marcado[/] como sospechoso.",
    }.get(policy_name, f"Política p={policy_name}.")
    return f"DMARC falló: ni SPF ni DKIM validan {visible} de forma alineada{why}. {consequence}"


def _show_delivery(
    message_id: str,
    smtp_accepted: bool,
    envelope_from: str,
    header_from: str,
    receptor_queue_id: str | None = None,
) -> None:
    if not smtp_accepted:
        return
    message, auth = _auth_results(message_id, receptor_queue_id)
    if not message:
        console.print("  [yellow]Todavía no aparece en Mailpit.[/] Revisa en unos segundos.")
        return
    if message["Subject"].startswith(QUARANTINE_TAG):
        console.print(
            f"  [yellow]Llegó MARCADO como sospechoso[/] (asunto «{escape(QUARANTINE_TAG)} …»).  "
            f"{_verdicts(auth)}"
        )
    else:
        console.print(f"  [green]Llegó a la bandeja del empleado[/] (Mailpit).  {_verdicts(auth)}")
    envelope, visible = _domain(envelope_from), _domain(header_from)
    meanings = (
        _interpret_spf(auth, envelope, visible),
        _interpret_dkim(auth, visible),
        _interpret_dmarc(auth, visible),
    )
    for meaning in meanings:
        if meaning:
            console.print(f"  [bold]Qué significa:[/] {meaning}")


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
            console.print(f"  [green]+ {line if len(line) < 90 else line[:87] + '…'}[/]")
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
    if result.emisor_confirmed:
        console.print(f"Firma DKIM del emisor: {firma} (confirmado por el emisor)")
    else:
        console.print(
            f"Firma DKIM del emisor: {firma}, [red]pero el emisor no lo confirmó[/]. "
            "Prueba `docker compose restart emisor`."
        )
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
        return (
            "[red]RECHAZADO[/]: el receptor lo bloqueó en la conversación SMTP. "
            "El correo nunca llegó a la bandeja del empleado."
        )
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
            if result.get("note"):
                console.print(f"  [dim]{result['note']}[/]")
            console.print(f"  Respuesta SMTP: {result['code']} {result['reply']}")
            console.print(f"  {_explain_smtp(result)}")
            _show_delivery(
                result["message_id"],
                result["accepted"],
                result["envelope_from"],
                result["header_from"],
                mailpit.queue_id(result["reply"]),
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


def cmd_reportes(args: argparse.Namespace) -> int:
    files = reportes.available()
    if args.archivo:
        files = [f for f in files if args.archivo in f.name]
    if not files:
        console.print(f"[red]✗ No encontré reportes en {reportes.REPORTS_DIR}.[/]")
        return 1

    for path in files:
        report = reportes.parse(path)
        console.print(
            Panel.fit(
                f"[bold]Reporte DMARC agregado de {report.org_name}[/]\n"
                f"Dominio: {report.domain} · política publicada: p={report.policy}\n"
                f"Período: {report.begin:%Y-%m-%d %H:%M} a {report.end:%Y-%m-%d %H:%M} UTC · "
                f"id {report.report_id}",
                border_style="cyan",
            )
        )
        table = Table()
        table.add_column("#", justify="right")
        table.add_column("IP de origen")
        table.add_column("Correos", justify="right")
        table.add_column("SPF")
        table.add_column("DKIM")
        table.add_column("Autenticó como")
        table.add_column("Diagnóstico")
        rows = sorted(report.rows, key=lambda r: -r.count)
        colors = {"Legítimo": "green", "Reenvío": "green", "Servicio sin alinear": "yellow"}
        for number, row in enumerate(rows, start=1):
            category, _ = row.verdict()
            passed = sorted({a.domain for a in row.auth if a.result == "pass"})
            table.add_row(
                str(number),
                row.source_ip,
                str(row.count),
                _colored(row.spf_aligned),
                _colored(row.dkim_aligned),
                "\n".join(passed) or "[dim](nada)[/]",
                f"[{colors.get(category, 'red')}]{category}[/]",
            )
        console.print(table)
        console.print("[dim]SPF y DKIM: resultado alineado con el From: (lo que evalúa DMARC).[/]")
        for number, row in enumerate(rows, start=1):
            console.print(f"  [bold]{number}.[/] {row.verdict()[1]}")
        console.print()

        failing = report.total - report.passing
        console.print(
            f"[bold]Resumen:[/] {report.passing} de {report.total} correos pasan DMARC "
            f"({100 * report.passing / report.total:.0f} %). "
            f"Con p=reject se rechazarían {failing}."
        )
        unaligned = sum(r.count for r in report.rows if r.verdict()[0] == "Servicio sin alinear")
        if unaligned:
            console.print(
                f"[yellow]Ojo:[/] {unaligned} de esos correos parecen legítimos (un servicio "
                "sin alinear). Corrígelo antes de pasar a quarantine o reject."
            )
    return 0


def _colored(result: str) -> str:
    return f"[green]{result}[/]" if result == "pass" else f"[red]{result}[/]"


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

    p = sub.add_parser("reportes", help="muestra los reportes DMARC agregados de ejemplo")
    p.add_argument("archivo", nargs="?", help="parte del nombre del archivo (opcional)")
    p.set_defaults(func=cmd_reportes)

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
