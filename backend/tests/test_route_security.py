"""Deny by default: a new endpoint that answers an anonymous caller makes this test fail.

It asks the app's own OpenAPI listing for every endpoint, calls each one with no credentials,
and requires a 401 unless the endpoint is on the explicit public list.
"""
import re
import uuid

import httpx

from app.main import app

PUBLIC = {
    ("GET", "/healthz"),
    ("GET", "/readyz"),
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/refresh"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/agent/enroll"),
}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def _all_endpoints():
    paths = app.openapi()["paths"]
    return {(m.upper(), p) for p, methods in paths.items() for m in methods if m.upper() in METHODS}


async def test_every_endpoint_rejects_anonymous_callers_unless_public():
    endpoints = _all_endpoints()
    protected = endpoints - PUBLIC
    assert len(protected) >= 5, f"too few protected endpoints found: {sorted(protected)}"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        for method, path in sorted(protected):
            url = re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)
            body = {} if method in {"POST", "PUT", "PATCH"} else None
            r = await client.request(method, url, json=body)
            assert r.status_code == 401, f"{method} {path} answered {r.status_code} to an anonymous caller"


def test_the_public_list_has_no_stale_entries():
    missing = PUBLIC - _all_endpoints()
    assert not missing, f"public list names endpoints that do not exist: {sorted(missing)}"
