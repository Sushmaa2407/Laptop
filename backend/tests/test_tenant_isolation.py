"""Two tenants, each with an agent. Everything one tenant does must be invisible to the other."""

import os
import uuid

import httpx
import pytest
from helpers import API, HEARTBEAT, enroll_agent, purge_domain, register_tenant, run_sql

from app.core.config import get_settings

pytestmark = pytest.mark.skipif(
    "TEST_DATABASE_URL" not in os.environ, reason="needs TEST_DATABASE_URL (run: source scripts/dev-env.sh)"
)

DOMAIN = "isolation-test.example.com"


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


@pytest.fixture
async def world(client):
    a = await register_tenant(client, DOMAIN, "Tenant A")
    b = await register_tenant(client, DOMAIN, "Tenant B")
    a_agent = await enroll_agent(client, a, name="a-laptop")
    b_agent = await enroll_agent(client, b, name="b-laptop")
    return {"a": a, "b": b, "a_agent": a_agent, "b_agent": b_agent}


async def test_each_tenant_lists_only_its_own_agents(client, world):
    la = (await client.get(f"{API}/agents", headers=world["a"]["headers"])).json()
    lb = (await client.get(f"{API}/agents", headers=world["b"]["headers"])).json()
    assert [x["id"] for x in la] == [world["a_agent"]["agent_id"]]
    assert [x["id"] for x in lb] == [world["b_agent"]["agent_id"]]


async def test_another_tenants_agent_is_indistinguishable_from_a_missing_one(client, world):
    other = await client.get(f"{API}/agents/{world['b_agent']['agent_id']}", headers=world["a"]["headers"])
    missing = await client.get(f"{API}/agents/{uuid.uuid4()}", headers=world["a"]["headers"])
    assert other.status_code == missing.status_code == 404
    assert other.json() == missing.json()


async def test_a_tenant_cannot_revoke_anothers_agent(client, world):
    r = await client.delete(f"{API}/agents/{world['b_agent']['agent_id']}", headers=world["a"]["headers"])
    assert r.status_code == 404
    still = (await client.get(f"{API}/agents/{world['b_agent']['agent_id']}", headers=world["b"]["headers"])).json()
    assert still["status"] == "active"
    hb = await client.post(f"{API}/agent/heartbeat", headers=world["b_agent"]["headers"], json=HEARTBEAT)
    assert hb.status_code == 204


async def test_a_heartbeat_touches_only_its_own_agent(client, world):
    await client.post(f"{API}/agent/heartbeat", headers=world["a_agent"]["headers"], json=HEARTBEAT)
    a = (await client.get(f"{API}/agents", headers=world["a"]["headers"])).json()[0]
    b = (await client.get(f"{API}/agents", headers=world["b"]["headers"])).json()[0]
    assert a["last_seen_at"] is not None and b["last_seen_at"] is None


async def test_a_code_enrolls_into_the_tenant_that_issued_it(client, world):
    third = await enroll_agent(client, world["a"], name="a-second")
    la = {x["id"] for x in (await client.get(f"{API}/agents", headers=world["a"]["headers"])).json()}
    lb = {x["id"] for x in (await client.get(f"{API}/agents", headers=world["b"]["headers"])).json()}
    assert third["agent_id"] in la and third["agent_id"] not in lb


async def test_user_tokens_and_agent_keys_are_not_interchangeable(client, world):
    a_user, a_key = world["a"]["headers"], world["a_agent"]["headers"]
    assert (await client.post(f"{API}/agent/heartbeat", headers=a_user, json=HEARTBEAT)).status_code == 401
    assert (await client.get(f"{API}/agents", headers=a_key)).status_code == 401
    assert (await client.get(f"{API}/me", headers=a_key)).status_code == 401
    r = await client.post(f"{API}/agents/enrollment-codes", headers=a_key, json={"agent_name": "x"})
    assert r.status_code == 401


async def test_database_functions_are_tenant_scoped(world):
    from app.db.session import get_sessionmaker
    from app.repositories import agents as agents_repo

    ta, tb = uuid.UUID(world["a"]["tenant_id"]), uuid.UUID(world["b"]["tenant_id"])
    a_id, b_id = uuid.UUID(world["a_agent"]["agent_id"]), uuid.UUID(world["b_agent"]["agent_id"])
    async with get_sessionmaker()() as s:
        assert await agents_repo.get_agent(s, tb, a_id) is None
        assert await agents_repo.get_agent(s, ta, a_id) is not None
        assert [x.id for x in await agents_repo.list_agents(s, tb)] == [b_id]
        assert await agents_repo.revoke_agent(s, tb, a_id) is False


async def test_deleting_a_tenant_removes_only_its_data(client, world):
    await run_sql("DELETE FROM tenants WHERE id = :t", t=world["a"]["tenant_id"])
    assert (
        await client.post(f"{API}/agent/heartbeat", headers=world["a_agent"]["headers"], json=HEARTBEAT)
    ).status_code == 401
    left = (await client.get(f"{API}/agents", headers=world["b"]["headers"])).json()
    assert [x["id"] for x in left] == [world["b_agent"]["agent_id"]]
