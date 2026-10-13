"""Renderiza y activa las zonas DNS del laboratorio.

Lo usan dos contenedores:
- `init`, al arrancar: renderiza las zonas de todos los escenarios con las llaves
  públicas DKIM y activa el escenario guardado en `estado/` (o el 0).
- `toolbox`, con `lab escenario <id>`: activa otro escenario ya renderizado.

Activar = copiar las zonas del escenario a `zonas/activas/` con un serial SOA nuevo
y guardar el escenario en `estado/estado.json`. CoreDNS ve el serial nuevo y recarga
la zona solo; el resto de contenedores lee `estado.json`. Nadie necesita docker.sock.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

DOMINIOS = ("bancoseguro.test", "atacante.test", "bancos3guro.test")

# Llaves DKIM: (dominio, selector). Las genera `init` con opendkim-genkey.
LLAVES_DKIM = (
    ("bancoseguro.test", "s2026"),
    ("atacante.test", "a2026"),
    ("bancos3guro.test", "p2026"),
)


@dataclass(frozen=True)
class Escenario:
    id: str
    nombre: str
    registros: tuple[str, ...]  # líneas extra en la zona de bancoseguro.test
    firma_dkim: bool  # ¿el emisor firma con DKIM?


# Cada fase agrega sus escenarios aquí (ver CLAUDE.md, sección 4).
ESCENARIOS: dict[str, Escenario] = {
    "0": Escenario("0", "Sin protección", (), firma_dkim=False),
    "1": Escenario(
        "1",
        "SPF",
        ('@         IN TXT  "v=spf1 ip4:172.28.0.10 -all"',),
        firma_dkim=False,
    ),
    "2": Escenario(
        "2",
        "SPF + DKIM",
        (
            '@         IN TXT  "v=spf1 ip4:172.28.0.10 -all"',
            "s2026._domainkey IN TXT {{DKIM_S2026}}",
        ),
        firma_dkim=True,
    ),
}

ESCENARIO_INICIAL = "0"
ARCHIVO_ESTADO = "estado.json"
MARCADOR_SERIAL = "{{SERIAL}}"


def leer_llave_publica(llaves: Path, dominio: str, selector: str) -> str:
    """Lee el TXT que genera opendkim-genkey y devuelve el valor completo del registro."""
    texto = (llaves / dominio / f"{selector}.txt").read_text(encoding="utf-8")
    valor = "".join(re.findall(r'"([^"]*)"', texto))
    if "p=" not in valor:
        raise ValueError(f"No encontré la llave pública en {selector}.txt de {dominio}")
    return valor


def txt_en_trozos(valor: str) -> str:
    """Un TXT admite cadenas de hasta 255 caracteres: parte la llave en varias."""
    trozos = [valor[i : i + 255] for i in range(0, len(valor), 255)]
    return "( " + " ".join(f'"{t}"' for t in trozos) + " )"


def renderizar_todo(plantillas: Path, llaves: Path, zonas: Path) -> None:
    """Genera zonas/escenarios/<id>/db.<dominio> para cada escenario."""
    marcadores = {
        f"{{{{DKIM_{selector.upper()}}}}}": txt_en_trozos(
            leer_llave_publica(llaves, dominio, selector)
        )
        for dominio, selector in LLAVES_DKIM
    }
    for escenario in ESCENARIOS.values():
        # Primero los registros del escenario: pueden contener marcadores {{DKIM_...}}.
        marcadores_escenario = {
            "{{REGISTROS_ESCENARIO}}": "\n".join(escenario.registros) or "; (ninguno)"
        } | marcadores
        destino = zonas / "escenarios" / escenario.id
        destino.mkdir(parents=True, exist_ok=True)
        for dominio in DOMINIOS:
            zona = (plantillas / f"db.{dominio}").read_text(encoding="utf-8")
            for linea in zona.splitlines():
                if linea.lstrip().startswith(";") and "{{" in linea:
                    raise ValueError(
                        f"db.{dominio}: un comentario contiene un marcador {{{{…}}}}; "
                        "se reemplazaría y podría crear registros por accidente"
                    )
            for marcador, valor in marcadores_escenario.items():
                zona = zona.replace(marcador, valor)
            pendientes = set(re.findall(r"\{\{[A-Z0-9_]+\}\}", zona)) - {MARCADOR_SERIAL}
            if pendientes:
                raise ValueError(f"Marcadores sin valor en db.{dominio}: {sorted(pendientes)}")
            escribir_atomico(destino / f"db.{dominio}", zona)


def escribir_atomico(ruta: Path, contenido: str) -> None:
    """Escribe en un temporal y lo renombra: CoreDNS nunca lee un archivo a medias."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=ruta.parent, prefix=".tmp-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(contenido)
    os.chmod(tmp, 0o644)  # CoreDNS corre como usuario sin privilegios
    os.replace(tmp, ruta)


def leer_estado(estado: Path) -> dict[str, object]:
    try:
        return json.loads((estado / ARCHIVO_ESTADO).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def nuevo_serial(anterior: int) -> int:
    """Serial con formato AAAAMMDDnn, siempre mayor que el anterior."""
    hoy = int(datetime.now(UTC).strftime("%Y%m%d00"))
    return max(hoy, anterior + 1)


def activar(escenario_id: str, zonas: Path, estado: Path) -> dict[str, object]:
    """Publica las zonas del escenario y guarda el estado. Devuelve el estado nuevo."""
    if escenario_id not in ESCENARIOS:
        disponibles = ", ".join(ESCENARIOS)
        raise ValueError(f"El escenario «{escenario_id}» no existe. Disponibles: {disponibles}")
    escenario = ESCENARIOS[escenario_id]
    serial = nuevo_serial(int(leer_estado(estado).get("serial", 0)))

    origen = zonas / "escenarios" / escenario.id
    for dominio in DOMINIOS:
        zona = (origen / f"db.{dominio}").read_text(encoding="utf-8")
        escribir_atomico(
            zonas / "activas" / f"db.{dominio}", zona.replace(MARCADOR_SERIAL, str(serial))
        )

    nuevo = {
        "escenario": escenario.id,
        "nombre": escenario.nombre,
        "firma_dkim": escenario.firma_dkim,
        "serial": serial,
        "activado": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    escribir_atomico(
        estado / ARCHIVO_ESTADO, json.dumps(nuevo, ensure_ascii=False, indent=2) + "\n"
    )
    return nuevo


def main() -> int:
    parser = argparse.ArgumentParser(description="Renderiza y activa las zonas DNS del laboratorio")
    parser.add_argument("--plantillas", type=Path, default=Path("/plantillas"))
    parser.add_argument("--llaves", type=Path, default=Path("/llaves"))
    parser.add_argument("--zonas", type=Path, default=Path("/zonas"))
    parser.add_argument("--estado", type=Path, default=Path("/estado"))
    args = parser.parse_args()

    try:
        renderizar_todo(args.plantillas, args.llaves, args.zonas)
        actual = str(leer_estado(args.estado).get("escenario", ESCENARIO_INICIAL))
        if actual not in ESCENARIOS:
            actual = ESCENARIO_INICIAL
        nuevo = activar(actual, args.zonas, args.estado)
    except (OSError, ValueError) as error:
        print(f"[init] Error al preparar las zonas DNS: {error}", file=sys.stderr)
        return 1
    print(f"[init] Zonas listas. Escenario activo: {nuevo['escenario']} (serial {nuevo['serial']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
