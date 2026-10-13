# Emisor: servidor de salida legítimo de bancoseguro.test (172.28.0.10).
# Postfix + OpenDKIM (selector s2026). Firma solo si el escenario activo lo pide.
FROM debian:trixie-20250929-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       postfix opendkim jq \
    && rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf
COPY opendkim.conf /etc/opendkim.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Sin chroot: Postfix usa el /etc/resolv.conf del contenedor tal cual.
RUN chmod 755 /usr/local/bin/entrypoint.sh \
    && postconf -F '*/*/chroot = n' \
    && postfix check

EXPOSE 25
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
