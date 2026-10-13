#!/usr/bin/env bash
# Punto de entrada en Linux, macOS y WSL: ./lab.sh <comando>
# Ejecuta la CLI `lab` dentro de la toolbox, en la red aislada del laboratorio.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $# -eq 0 ]]; then
  set -- --help
fi

exec docker compose run --rm toolbox lab "$@"
