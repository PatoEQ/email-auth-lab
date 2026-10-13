"""API mínima del reenviador, solo accesible dentro de lab-net.

  GET  /salud      → {"ok": true}
  POST /reenviar   → cuerpo JSON opcional {"modo": "tal-cual" | "lista"}

Toma el último correo legítimo firmado del director y lo reenvía desde 172.28.0.40:
- tal-cual: como un reenvío automático. No toca nada: SPF falla (otra IP), DKIM sobrevive.
- lista:    como una lista de correo. Agrega una etiqueta al asunto y un pie: DKIM se rompe.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from correo_lab import (
    ALLOWED_SERVER,
    DEFAULT_RECIPIENT,
    Attack,
    AttackError,
    AttackResult,
    DestinationError,
    decode_body,
    encode_body,
    header_value,
    join_message,
    latest_legit_message,
    send_raw,
    validate_destination,
    without_trace_headers,
)

PORT = 8080
LIST_TAG = b"[Asociacion Bancaria]"  # ASCII: el asunto no necesita codificación
LIST_ID = b"List-Id: Socios <socios.asociacion-bancaria.test>"
LIST_FOOTER = (
    "\n--\nRecibiste este correo por la lista socios@asociacion-bancaria.test.\n"
    "Para darte de baja, escribe a socios-baja@asociacion-bancaria.test.\n"
)


def forward(mode: str, recipient: str = DEFAULT_RECIPIENT) -> AttackResult:
    validate_destination(recipient, ALLOWED_SERVER)
    original, signed = latest_legit_message()
    blocks, eol, body = without_trace_headers(original)
    message_id = header_value(blocks, b"Message-ID").decode().strip("<>")
    header_from = header_value(blocks, b"From").decode()

    if mode == "lista":
        for block in blocks:
            if block[0].lower().startswith(b"subject:"):
                block[0] = b"Subject: " + LIST_TAG + b" " + block[0].split(b":", 1)[1].strip()
        blocks.append([LIST_ID])
        cte = header_value(blocks, b"Content-Transfer-Encoding")
        body = encode_body(decode_body(body, cte) + LIST_FOOTER.encode(), cte, eol)
        # Las listas envían con su propio sobre (los rebotes van a la lista).
        envelope = "socios-rebotes@asociacion-bancaria.test"
        description = "Lista de correo (asunto y pie modificados)"
    else:
        # Reenvío clásico: mantiene el sobre original del remitente.
        envelope = "director@bancoseguro.test"
        description = "Reenvío automático (sin cambios)"

    sender = Attack(
        id="lista" if mode == "lista" else "tal-cual",
        description=description,
        envelope_from=envelope,
        header_from=header_from,
        dkim="la original del banco" if signed else "ninguna",
    )
    note = "" if signed else "Ojo: el último correo legítimo no estaba firmado con DKIM."
    return send_raw(
        sender,
        join_message(blocks, eol, body),
        message_id,
        recipient,
        note=note,
        helo="reenvio.asociacion-bancaria.test",
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "reenviador-lab/1"

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (nombre impuesto por http.server)
        if self.path == "/salud":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "Ruta desconocida"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/reenviar":
            self._json(404, {"error": "Ruta desconocida"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            options = json.loads(self.rfile.read(length) or b"{}")
            mode = str(options.get("modo", "tal-cual"))
        except (ValueError, AttributeError):
            self._json(400, {"error": "Cuerpo JSON inválido"})
            return
        if mode not in ("tal-cual", "lista"):
            self._json(400, {"error": "Modo desconocido: usa «tal-cual» o «lista»"})
            return
        try:
            result = forward(mode)
        except DestinationError as error:
            self._json(400, {"error": str(error)})
            return
        except AttackError as error:
            self._json(409, {"error": str(error)})
            return
        self._json(200, result.to_dict())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"[reenviador] {self.address_string()} {format % args}", flush=True)


if __name__ == "__main__":
    print(f"[reenviador] API escuchando en :{PORT} (solo lab-net)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
