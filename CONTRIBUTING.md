# Cómo contribuir

¡Gracias por tu interés! Las contribuciones son bienvenidas: correcciones, mejoras de la documentación, nuevos escenarios o traducciones.

## Antes de empezar

- Lee [CLAUDE.md](CLAUDE.md). Es el contrato del proyecto: reglas no negociables, arquitectura, registros DNS por escenario, catálogo de ataques y la **tabla de verdad**.
- Para cambios grandes (un escenario o un servicio nuevo), abre primero un issue para conversarlo.
- Los problemas de seguridad se reportan en privado: ver [SECURITY.md](SECURITY.md).

## Reglas que no se negocian

1. Solo dominios `.test` (y 192.0.2.0/24 en ejemplos). Nunca un dominio ni una IP real.
2. `lab-net` sigue siendo `internal: true`.
3. Los ataques validan el destino.
4. Ningún secreto en el repo: nada de llaves "de ejemplo".
5. Sin `docker.sock` dentro de los contenedores.
6. Puertos al host solo en `127.0.0.1`.
7. Finales de línea LF.

## Entorno de desarrollo

```bash
docker compose --profile extras up -d --build --wait
./lab.sh estado
```

Después de cambiar código de un servicio, reconstrúyelo con `docker compose up -d --build <servicio>`. La toolbox se reconstruye con `docker compose up -d --build` aunque no arranque (`scale: 0`).

## Verificar tus cambios

Todo esto lo corre la CI. Córrelo localmente antes del pull request:

```bash
# Tests (unos 9 minutos; la tabla de verdad completa)
docker compose run --rm toolbox pytest -q

# Solo un archivo o un test
docker compose run --rm toolbox pytest -q tests/test_fase7.py -k verificar

# Lint y formato de Python
docker run --rm -v "$PWD":/io -w /io ghcr.io/astral-sh/ruff:0.14.0 check .
docker run --rm -v "$PWD":/io -w /io ghcr.io/astral-sh/ruff:0.14.0 format .

# Scripts de shell
docker run --rm -v "$PWD":/mnt koalaman/shellcheck:v0.11.0 \
  lab.sh init/entrypoint.sh receptor/entrypoint.sh emisor/entrypoint.sh atacante/entrypoint.sh
```

Y antes de cada commit: `git status` no debe mostrar llaves, `.env` ni volúmenes.

## Convenciones

- **Python 3.12** con type hints, `ruff` (lint y formato; configuración en `pyproject.toml`) y `pytest`.
- **Shell** con `set -euo pipefail`, sin observaciones de `shellcheck`.
- **Idioma:**
  - nombres de archivos y carpetas en español;
  - identificadores de código en inglés;
  - mensajes al usuario, documentación y comentarios explicativos en español claro.
- **CLI:** mensajes cortos, con colores (`rich`), que siempre dicen **qué significa** el resultado.
- **Imágenes Docker** con versión fija (nunca `latest`).
- **README de escenario** con estas secciones: Objetivo · Qué se configura · Pasos · Resultado esperado · Qué aprendimos y qué sigue sin cubrirse · Preguntas para la audiencia.
- Si cambias la salida de la CLI que aparece en la documentación, regenera las capturas:
  `docker compose run --rm -v ./docs/img:/salida toolbox python -m lab.capturas /salida`.

## La tabla de verdad

[`tests/test_matriz.py`](tests/test_matriz.py) verifica cada celda de la tabla de verdad de CLAUDE.md contra el laboratorio real. Si un cambio hace que la realidad contradiga la tabla, **no cambies la tabla en silencio**: explica en el pull request por qué cambió el comportamiento y propón el ajuste.

## Pull requests

- Una idea por pull request, con commits descriptivos en español.
- Describe qué cambia, por qué y cómo lo verificaste.
- La CI debe pasar en verde.
