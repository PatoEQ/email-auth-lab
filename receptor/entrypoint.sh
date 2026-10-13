#!/usr/bin/env bash
# Arranca Rspamd en segundo plano y Postfix en primer plano.
set -euo pipefail

mkdir -p /run/rspamd
chown _rspamd:_rspamd /run/rspamd

rspamd -u _rspamd -g _rspamd -f &

# Espera a que el milter escuche antes de aceptar correo.
for _ in $(seq 1 30); do
  if rspamadm control stat >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

exec postfix start-fg
