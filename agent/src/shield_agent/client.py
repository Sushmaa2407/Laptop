"""Tiny HTTPS client for the Shield server (standard library only, so the agent has no extra dependencies).

Every call either returns data or raises:
  NetworkError - could not reach the server (caller keeps its data and retries later)
  ApiError     - the server answered with an error status
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

API = "/api/v1"


class NetworkError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class ShieldClient:
    def __init__(self, server_url: str, api_key: str | None = None, ca_cert: str | None = None, timeout: float = 10.0):
        self._base = server_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        # Verify the server certificate. With a private CA (Caddy "tls internal") we trust exactly that CA file.
        self._ssl = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()

    def _request(self, method: str, path: str, body: Any = None, *, auth: bool = True) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self._base + API + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if auth and self._api_key:
            req.add_header("Authorization", f"Bearer {self._api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise ApiError(exc.code, detail) from None
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError) as exc:
            raise NetworkError(str(exc)) from None
        return json.loads(raw) if raw else None

    # ---- endpoints
    def enroll(self, code: str, platform: str, version: str) -> dict:
        return self._request("POST", "/agent/enroll", {"code": code, "platform": platform, "version": version}, auth=False)

    def heartbeat(self, payload: dict) -> None:
        self._request("POST", "/agent/heartbeat", payload)

    def send_flows(self, flows: list[dict]) -> None:
        self._request("POST", "/agent/telemetry", {"schema_version": 1, "flows": flows})

    def pull_commands(self) -> list[dict]:
        return self._request("GET", "/agent/commands") or []

    def ack_command(self, command_id: str, state: str, result: str = "") -> None:
        self._request("POST", f"/agent/commands/{command_id}/ack", {"state": state, "result": result[:200]})
