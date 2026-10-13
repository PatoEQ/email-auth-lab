# Atacante (172.28.0.66): lanza los ataques A1–A6 con swaks (y dkimpy para firmar).
# Expone una API mínima solo dentro de lab-net para que `lab atacar` la invoque
# sin necesidad de docker.sock.
FROM debian:trixie-20250929-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends swaks python3 python3-dkim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/atacante
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY servidor.py ./
COPY ataques/ ./ataques/

RUN chmod 755 /usr/local/bin/entrypoint.sh \
    && useradd --system --no-create-home atacante

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python3", "servidor.py"]
