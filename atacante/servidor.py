"""API mínima del atacante, solo accesible dentro de lab-net (no publica puertos al host).

  GET  /salud          → {"ok": true}
  GET  /ataques        → catálogo
  POST /atacar/<ID>    → lanza el ataque; cuerpo JSON opcional {"para": ..., "servidor": ...}

Solo ejecuta ataques del catálogo; los destinos se validan en cada ataque.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ataques import CATALOG
from ataques.comun import ALLOWED_SERVER, DEFAULT_RECIPIENT, DestinationError

PORT = 8080


class Handler(BaseHTTPRequestHandler):
    server_version = "atacante-lab/1"

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
        elif self.path == "/ataques":
            self._json(200, [asdict(attack) for attack, _ in CATALOG.values()])
        else:
            self._json(404, {"error": "Ruta desconocida"})

    def do_POST(self) -> None:  # noqa: N802
        prefix = "/atacar/"
        attack_id = self.path.removeprefix(prefix).upper()
        if not self.path.startswith(prefix) or attack_id not in CATALOG:
            disponibles = ", ".join(CATALOG)
            self._json(404, {"error": f"Ataque desconocido. Disponibles: {disponibles}"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            options = json.loads(self.rfile.read(length) or b"{}")
            recipient = str(options.get("para", DEFAULT_RECIPIENT))
            server = str(options.get("servidor", ALLOWED_SERVER))
        except (ValueError, AttributeError):
            self._json(400, {"error": "Cuerpo JSON inválido"})
            return
        _, launch = CATALOG[attack_id]
        try:
            result = launch(recipient, server)
        except DestinationError as error:
            self._json(400, {"error": str(error)})
            return
        self._json(200, result.to_dict())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"[atacante] {self.address_string()} {format % args}", flush=True)


if __name__ == "__main__":
    print(f"[atacante] API escuchando en :{PORT} (solo lab-net)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
