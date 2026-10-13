"""Cliente mínimo de la API de Mailpit."""

from __future__ import annotations

import json
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


def delete_all() -> None:
    _request("/messages", method="DELETE")


def find_by_message_id(message_id: str) -> dict[str, Any] | None:
    found = _request(f"/search?query={quote(f'message-id:"{message_id}"')}")["messages"]
    return found[0] if found else None


def wait_for_message_id(message_id: str, timeout: float = 20.0) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        message = find_by_message_id(message_id)
        if message:
            return message
        time.sleep(0.5)
    return None


def headers(mailpit_id: str) -> dict[str, list[str]]:
    return _request(f"/message/{mailpit_id}/headers")
