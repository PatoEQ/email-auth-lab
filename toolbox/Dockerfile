# Toolbox: CLI `lab` y tests. Corre bajo demanda con `docker compose run --rm toolbox ...`.
FROM python:3.12.12-slim-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# El mismo módulo que usa `init`, para que activar un escenario funcione igual en ambos.
COPY --from=init renderizar_zonas.py /opt/init/renderizar_zonas.py
ENV PYTHONPATH=/opt/init

COPY pyproject.toml /opt/lab/pyproject.toml
COPY lab/ /opt/lab/lab/
RUN pip install --no-cache-dir --no-deps /opt/lab

WORKDIR /lab
CMD ["lab", "--help"]
