#!/usr/bin/env bash
# Copia las llaves DKIM del atacante (solo las suyas: atacante.test y bancos3guro.test)
# para el usuario sin privilegios y luego baja privilegios. La llave del banco nunca
# se monta en este contenedor.
set -euo pipefail

DESTINO=/run/atacante/llaves
install -d -o atacante -g atacante -m 700 "${DESTINO}"
install -o atacante -g atacante -m 400 /llaves/atacante.test/a2026.private "${DESTINO}/a2026.private"
install -o atacante -g atacante -m 400 /llaves/bancos3guro.test/p2026.private "${DESTINO}/p2026.private"

exec setpriv --reuid=atacante --regid=atacante --init-groups "$@"
