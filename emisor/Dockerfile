# Emisor: servidor de salida legítimo de bancoseguro.test (172.28.0.10).
# Fase 2: solo Postfix. En la fase 4 se agrega OpenDKIM para firmar.
FROM debian:trixie-20250929-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix \
    && rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf

# Sin chroot: Postfix usa el /etc/resolv.conf del contenedor tal cual.
RUN postconf -F '*/*/chroot = n' \
    && postfix check

EXPOSE 25
CMD ["postfix", "start-fg"]
