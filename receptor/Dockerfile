# Receptor: MX de bancoseguro.test. Postfix recibe, Rspamd (milter) verifica SPF/DKIM/DMARC.
FROM debian:trixie-20250929-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       postfix rspamd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf
COPY transport /etc/postfix/transport
COPY rspamd/ /etc/rspamd/local.d/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Sin chroot: Postfix usa el /etc/resolv.conf del contenedor tal cual.
RUN chmod 755 /usr/local/bin/entrypoint.sh \
    && postmap /etc/postfix/transport \
    && postconf -F '*/*/chroot = n' \
    && postfix check

EXPOSE 25
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
