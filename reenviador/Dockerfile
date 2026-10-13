# Reenviador (172.28.0.40, perfil `extras`): solo para el escenario 5.
# Simula un reenvío automático o una lista de correo que reenvía correo del banco.
FROM debian:trixie-20250929-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends swaks python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/reenviador
# Validación de destino y envío con swaks: los mismos que usa el atacante.
COPY --from=ataques comun.py ./correo_lab.py
COPY servidor.py ./

RUN useradd --system --no-create-home reenviador
USER reenviador

EXPOSE 8080
CMD ["python3", "servidor.py"]
