#!/usr/bin/env bash
# Arranca OpenDKIM y Postfix, y vigila el escenario activo en /estado/estado.json.
# Cambio de escenario sin docker.sock: si el escenario pide firmar, Postfix usa OpenDKIM
# como milter; si no, lo quita. Se aplica con `postfix reload`, sin reiniciar el contenedor.
# Al terminar, escribe /estado/emisor.json para que `lab escenario` sepa que ya se aplicó.
set -euo pipefail

ESTADO=/estado/estado.json
CONFIRMACION=/estado/emisor.json
MILTER=inet:127.0.0.1:8891

# OpenDKIM exige que la llave privada sea suya y no la pueda leer nadie más.
install -d -o opendkim -g opendkim -m 700 /etc/opendkim/llaves /run/opendkim
install -o opendkim -g opendkim -m 600 /llaves/s2026.private /etc/opendkim/llaves/s2026.private

leer() {  # leer <campo> <valor por defecto>
  jq -r ".$1 // \"$2\"" "${ESTADO}" 2>/dev/null || echo "$2"
}

aplicar_estado() {
  local firma serial
  firma=$(leer firma_dkim false)
  serial=$(leer serial 0)
  if [[ "${firma}" == "true" ]]; then
    postconf -e "smtpd_milters = ${MILTER}" "non_smtpd_milters = ${MILTER}"
  else
    postconf -e "smtpd_milters =" "non_smtpd_milters ="
  fi
  if postfix status >/dev/null 2>&1; then
    postfix reload >/dev/null 2>&1
  fi
  jq -n --argjson firma "${firma}" --argjson serial "${serial}" \
    '{firma_dkim: $firma, serial: $serial}' > "${CONFIRMACION}.tmp"
  mv "${CONFIRMACION}.tmp" "${CONFIRMACION}"
  echo "[emisor] Escenario con serial ${serial}: firma DKIM $([[ "${firma}" == "true" ]] && echo activada || echo desactivada)."
}

vigilar_estado() {
  local ultimo actual
  ultimo=$(leer serial 0)
  while sleep 1; do
    actual=$(leer serial 0)
    if [[ "${actual}" != "${ultimo}" ]]; then
      aplicar_estado
      ultimo=${actual}
    fi
  done
}

aplicar_estado
opendkim -f -x /etc/opendkim.conf &

# Espera a que OpenDKIM escuche antes de aceptar correo.
for _ in $(seq 1 30); do
  if (exec 3<>/dev/tcp/127.0.0.1/8891) 2>/dev/null; then
    break
  fi
  sleep 1
done

vigilar_estado &
exec postfix start-fg
