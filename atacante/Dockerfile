# Atacante (172.28.0.66): lanza los ataques A1–A6 con swaks.
# Expone una API mínima solo dentro de lab-net para que `lab atacar` la invoque
# sin necesidad de docker.sock.
FROM debian:trixie-20250929-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends swaks python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/atacante
COPY servidor.py ./
COPY ataques/ ./ataques/

RUN useradd --system --no-create-home atacante
USER atacante

EXPOSE 8080
CMD ["python3", "servidor.py"]
