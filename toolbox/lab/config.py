"""Direcciones y rutas del laboratorio (ver CLAUDE.md, sección 3)."""

from __future__ import annotations

from pathlib import Path

DNS_SERVER = "172.28.0.53"
RECEPTOR = "receptor"
EMISOR = "emisor"
MAILPIT_API = "http://mailpit:8025/api/v1"
ATACANTE_API = "http://atacante:8080"

VICTIM_DOMAIN = "bancoseguro.test"
ZONE_TTL = 5  # segundos; igual al $TTL de las plantillas en dns/plantillas/
DKIM_SELECTOR = "s2026"
EMPLOYEE = "empleado@bancoseguro.test"
DIRECTOR = "director@bancoseguro.test"

ZONAS_DIR = Path("/zonas")
ESTADO_DIR = Path("/estado")
