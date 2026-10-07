import os
import uuid

import httpx
import pytest
import redis.asyncio as aioredis
from sqlalchemy import text

from app.core.config import get_settings
from app.core.redis_client import redis_client

pytestmark = pytest.mark.skipif(
    "TEST_DATABASE_URL" not in os.environ or "TEST_REDIS_URL" not in os.environ,
    reason="needs TEST_DATABASE_URL and TEST_REDIS_URL (run: source scripts/dev-env.sh)",
)

DOMAIN = "ratelimit-test.example.com"
PASSWORD = "correct horse battery"
WRONG = "wrong password here"
API = "/api/v1"


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "t" * 48)
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _flush():
    # Always use the TEST redis, even while a test has pointed REDIS_URL somewhere else.
    r = aioredis.from_url(os.environ["TEST_REDIS_URL"])
    try:
        await r.flushdb()
    finally:
        await r.aclose()


async def _purge():
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as s:
        await s.execute(
            text(f"DELETE FROM tenants WHERE id IN (SELECT tenant_id FROM users WHERE email LIKE '%@{DOMAIN}')")
        )
        await s.commit()


@pytest.fixture(autouse=True)
async def _clean(_settings):
    await _flush()
    await _purge()
    yield
    await _flush()
    await _purge()


@pytest.fixture
async def client():
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


def new_email():
    return f"user-{uuid.uuid4().hex[:8]}@{DOMAIN}"


async def register(client, email=None):
    email = email or new_email()
    r = await client.post(
        f"{API}/auth/register", json={"email": email, "password": PASSWORD, "tenant_name": "Acme"}
    )
    return email, r


async def login(client, email, password):
    return await client.post(f"{API}/auth/login", json={"email": email, "password": password})


async def test_failed_logins_lock_the_account_then_recover(client):
    email, r = await register(client)
    assert r.status_code == 201
    for _ in range(5):
        assert (await login(client, email, WRONG)).status_code == 401
    locked = await login(client, email, WRONG)
    assert locked.status_code == 429 and int(locked.headers["retry-after"]) > 0
    # While locked even the CORRECT password is refused, so a right guess reveals nothing.
    assert (await login(client, email, PASSWORD)).status_code == 429
    await _flush()  # stands in for the 15 minutes passing
    assert (await login(client, email, PASSWORD)).status_code == 200


async def test_successful_login_clears_the_failure_counter(client):
    email, _ = await register(client)
    for _ in range(3):
        assert (await login(client, email, WRONG)).status_code == 401
    assert (await login(client, email, PASSWORD)).status_code == 200
    for _ in range(4):  # would have been refused after 2 more if the counter had not been cleared
        assert (await login(client, email, WRONG)).status_code == 401


async def test_registration_is_limited_per_ip(client):
    for _ in range(5):
        _, r = await register(client)
        assert r.status_code == 201
    _, r = await register(client)
    assert r.status_code == 429


async def test_one_ip_cannot_spray_many_accounts(client):
    for i in range(30):
        r = await login(client, new_email(), WRONG)
        assert r.status_code == 401, i
    assert (await login(client, new_email(), WRONG)).status_code == 429


async def test_redis_keys_contain_no_raw_emails_or_ips(client):
    email = new_email()
    await login(client, email, WRONG)
    async with redis_client() as r:
        keys = await r.keys("rl:*")
    assert keys, "expected rate-limit keys"
    for key in keys:
        assert "@" not in key and email not in key and "127.0.0.1" not in key


async def test_fails_closed_when_redis_is_down(client, monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    assert (await login(client, new_email(), WRONG)).status_code == 503
    _, r = await register(client)
    assert r.status_code == 503


async def test_limits_can_be_switched_off(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    get_settings.cache_clear()
    email, _ = await register(client)
    for _ in range(7):
        assert (await login(client, email, WRONG)).status_code == 401
