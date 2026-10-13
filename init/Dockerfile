# Init: genera las llaves DKIM si faltan y renderiza las zonas DNS. Corre una vez y termina.
FROM python:3.12.12-slim-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends opendkim-tools \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY renderizar_zonas.py /opt/init/renderizar_zonas.py
RUN chmod 755 /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
