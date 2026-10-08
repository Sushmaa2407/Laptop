import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.core.config import get_settings
from helpers import API, HEARTBEAT, enroll_agent, purge_domain, register_tenant, run_sql

pytestmark = pytest.mark.skipif(
    "TEST_DATABASE_URL" not in os.environ, reason="needs TEST_DATABASE_URL (run: source scripts/dev-env.sh)"
)

DOMAIN = "agents-test.example.com"


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "t" * 48)
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
async def _clean(_settings):
    await purge_domain(DOMAIN)
    yield
    await purge_domain(DOMAIN)


@pytest.fixture
async def client():
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def new_code(client, tenant, name="dev laptop"):
    r = await client.post(f"{API}/agents/enrollment-codes", headers=tenant["headers"], json={"agent_name": name})
    assert r.status_code == 201, r.text
    return r.json()["code"]


def enroll_body(code, **over):
    return {"code": code, "platform": "linux", "version": "0.1.0", **over}


async def test_creating_a_code_requires_login(client):
    r = await client.post(f"{API}/agents/enrollment-codes", json={"agent_name": "x"})
    assert r.status_code == 401


async def test_full_enrollment_flow(client):
    t = await register_tenant(client, DOMAIN)
    r = await client.post(f"{API}/agents/enrollment-codes", headers=t["headers"], json={"agent_name": "dev laptop"})
    assert r.status_code == 201 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert set(body) == {"code", "agent_name", "expires_at"} and len(body["code"]) >= 16
    expires = datetime.fromisoformat(body["expires_at"])
    now = datetime.now(timezone.utc)
    assert now + timedelta(minutes=14) < expires < now + timedelta(minutes=16)

    e = await client.post(f"{API}/agent/enroll", json=enroll_body(body["code"]))
    assert e.status_code == 201 and e.headers["cache-control"] == "no-store"
    assert set(e.json()) == {"agent_id", "api_key", "agent_name"}
    assert e.json()["api_key"].startswith("shk_") and e.json()["agent_name"] == "dev laptop"

    listing = (await client.get(f"{API}/agents", headers=t["headers"])).json()
    assert len(listing) == 1
    assert set(listing[0]) == {"id", "name", "platform", "version", "status", "last_seen_at", "created_at"}
    assert listing[0]["status"] == "active" and listing[0]["last_seen_at"] is None
    assert listing[0]["platform"] == "linux" and listing[0]["version"] == "0.1.0"


async def test_secrets_are_stored_only_as_hashes(client):
    t = await register_tenant(client, DOMAIN)
    a = await enroll_agent(client, t)
    key_hash = (await run_sql("SELECT api_key_hash FROM agents WHERE id = :i", i=a["agent_id"])).scalar_one()
    assert len(key_hash) == 64 and key_hash != a["api_key"] and a["api_key"] not in key_hash
    code_hashes = (
        await run_sql("SELECT code_hash FROM enrollment_codes WHERE tenant_id = :t", t=t["tenant_id"])
    ).scalars().all()
    assert code_hashes and all(len(h) == 64 and h != a["code"] for h in code_hashes)


async def test_a_code_works_only_once(client):
    t = await register_tenant(client, DOMAIN)
    code = await new_code(client, t)
    assert (await client.post(f"{API}/agent/enroll", json=enroll_body(code))).status_code == 201
    second = await client.post(f"{API}/agent/enroll", json=enroll_body(code))
    unknown = await client.post(f"{API}/agent/enroll", json=enroll_body("this-code-does-not-exist"))
    assert second.status_code == unknown.status_code == 401
    assert second.json() == unknown.json()  # used and unknown codes look identical
    assert len((await client.get(f"{API}/agents", headers=t["headers"])).json()) == 1


async def test_an_expired_code_is_rejected(client):
    t = await register_tenant(client, DOMAIN)
    code = await new_code(client, t)
    await run_sql(
        "UPDATE enrollment_codes SET expires_at = now() - interval '1 minute' WHERE tenant_id = :t",
        t=t["tenant_id"],
    )
    assert (await client.post(f"{API}/agent/enroll", json=enroll_body(code))).status_code == 401
    assert (await client.get(f"{API}/agents", headers=t["headers"])).json() == []


async def test_bad_input_is_rejected(client):
    t = await register_tenant(client, DOMAIN)
    code = await new_code(client, t)
    for bad in [
        enroll_body(code, platform="solaris"),
        enroll_body(code, version="1.0; rm -rf /"),
        enroll_body(code, tenant_id="abc"),
        enroll_body("abc"),
    ]:
        assert (await client.post(f"{API}/agent/enroll", json=bad)).status_code == 422
    for bad in [{"agent_name": ""}, {"agent_name": "x" * 101}, {"agent_name": "ok", "tenant_id": t["tenant_id"]}]:
        r = await client.post(f"{API}/agents/enrollment-codes", headers=t["headers"], json=bad)
        assert r.status_code == 422
    # the good code was never consumed by the failed attempts
    assert (await client.post(f"{API}/agent/enroll", json=enroll_body(code))).status_code == 201


async def test_heartbeat_updates_last_seen_and_version(client):
    t = await register_tenant(client, DOMAIN)
    a = await enroll_agent(client, t)
    r = await client.post(f"{API}/agent/heartbeat", headers=a["headers"], json=HEARTBEAT)
    assert r.status_code == 204
    agent = (await client.get(f"{API}/agents/{a['agent_id']}", headers=t["headers"])).json()
    assert agent["last_seen_at"] is not None and agent["version"] == "0.1.1"


async def test_heartbeat_rejects_bad_payloads(client):
    t = await register_tenant(client, DOMAIN)
    a = await enroll_agent(client, t)
    missing = {k: v for k, v in HEARTBEAT.items() if k != "uptime_s"}
    for bad in [{**HEARTBEAT, "packets_dropped": -1}, {**HEARTBEAT, "tenant_id": t["tenant_id"]}, missing, {}]:
        assert (await client.post(f"{API}/agent/heartbeat", headers=a["headers"], json=bad)).status_code == 422


async def test_heartbeat_needs_a_valid_agent_key(client):
    for headers in [
        {}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"},
        {"Authorization": "Bearer shk_nonsense"}, {"Authorization": "Bearer nokeyprefix"},
        {"Authorization": "Bearer shk_" + "x" * 5000},
    ]:
        r = await client.post(f"{API}/agent/heartbeat", headers=headers, json=HEARTBEAT)
        assert r.status_code == 401, headers


async def test_a_revoked_agent_is_cut_off_immediately(client):
    t = await register_tenant(client, DOMAIN)
    a = await enroll_agent(client, t)
    assert (await client.post(f"{API}/agent/heartbeat", headers=a["headers"], json=HEARTBEAT)).status_code == 204
    assert (await client.delete(f"{API}/agents/{a['agent_id']}", headers=t["headers"])).status_code == 204
    assert (await client.post(f"{API}/agent/heartbeat", headers=a["headers"], json=HEARTBEAT)).status_code == 401
    assert (await client.delete(f"{API}/agents/{a['agent_id']}", headers=t["headers"])).status_code == 204  # idempotent
    listed = (await client.get(f"{API}/agents", headers=t["headers"])).json()
    assert listed[0]["status"] == "revoked"
