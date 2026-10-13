"""Cliente mínimo de la API de Mailpit."""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from lab.config import MAILPIT_API


def _request(path: str, method: str = "GET") -> Any:
    with urlopen(Request(f"{MAILPIT_API}{path}", method=method), timeout=5) as resp:
        body = resp.read()
    return json.loads(body) if body.strip().startswith((b"{", b"[")) else body


def info() -> dict[str, Any]:
    return _request("/info")


def latest() -> dict[str, Any] | None:
    """El correo más reciente de la bandeja."""
    messages = _request("/messages?limit=1")["messages"]
    return messages[0] if messages else None


def delete_all() -> None:
    _request("/messages", method="DELETE")


def queue_id(smtp_reply: str) -> str | None:
    """Id de cola del receptor en «250 2.0.0 Ok: queued as 59F9035438»."""
    match = re.search(r"queued as (\w+)", smtp_reply)
    return match.group(1) if match else None


def find_by_message_id(
    message_id: str, receptor_queue_id: str | None = None
) -> dict[str, Any] | None:
    """Busca por Message-ID. Si hay varias copias (A3 reutiliza el Message-ID del correo
    original), `receptor_queue_id` elige la entrega exacta por su cabecera Received."""
    found = _request(f"/search?query={quote(f'message-id:"{message_id}"')}")["messages"]
    if receptor_queue_id is None:
        return found[0] if found else None
    for message in found:
        received = " ".join(headers(message["ID"]).get("Received", []))
        if re.search(rf"\bid {re.escape(receptor_queue_id)}\b", received):
            return message
    return None


def wait_for_message_id(
    message_id: str, receptor_queue_id: str | None = None, timeout: float = 20.0
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        message = find_by_message_id(message_id, receptor_queue_id)
        if message:
            return message
        time.sleep(0.5)
    return None


def raw(mailpit_id: str) -> bytes:
    return _request(f"/message/{mailpit_id}/raw")


def headers(mailpit_id: str) -> dict[str, list[str]]:
    return _request(f"/message/{mailpit_id}/headers")
