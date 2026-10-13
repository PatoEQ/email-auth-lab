# Toolbox: herramientas del laboratorio. En la fase 1 solo corre los tests;
# en la fase 2 se agrega la CLI `lab`.
FROM python:3.12.12-slim-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /lab
CMD ["pytest", "-q"]
