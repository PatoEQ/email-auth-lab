#!/usr/bin/env bash
# Genera las llaves DKIM que falten (RSA 2048) y renderiza las zonas DNS.
# Las llaves viven en el volumen `llaves`; nunca en el repositorio.
set -euo pipefail

generar_llave() {
  local dominio=$1 selector=$2
  local dir="/llaves/${dominio}"
  if [[ -f "${dir}/${selector}.private" ]]; then
    echo "[init] Llave DKIM ${selector} de ${dominio}: ya existe, se reutiliza."
    return
  fi
  mkdir -p "${dir}"
  opendkim-genkey -b 2048 -h sha256 -d "${dominio}" -s "${selector}" -D "${dir}"
  chmod 600 "${dir}/${selector}.private"
  echo "[init] Llave DKIM ${selector} de ${dominio}: generada (RSA 2048)."
}

generar_llave bancoseguro.test s2026
generar_llave atacante.test a2026
generar_llave bancos3guro.test p2026

exec python3 /opt/init/renderizar_zonas.py
