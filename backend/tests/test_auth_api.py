import os
import uuid

import httpx
import pytest
from sqlalchemy import text

from app.core import security
from app.core.config import get_settings

pytestmark = pytest.mark.skipif(
    "TEST_DATABASE_URL" not in os.environ,
    reason="needs TEST_DATABASE_URL (run: source scripts/dev-env.sh)",
)

DOMAIN = "shield-test.example.com"
PASSWORD = "correct horse battery"
API = "/api/v1"


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "t" * 48)
    monkeypatch.setenv("COOKIE_SECURE", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _run_sql(sql: str, **params):
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as s:
        result = await s.execute(text(sql), params)
        await s.commit()
        return result


async def _purge():
    await _run_sql(
        f"DELETE FROM tenants WHERE id IN (SELECT tenant_id FROM users WHERE email LIKE '%@{DOMAIN}')"
    )


@pytest.fixture(autouse=True)
async def _clean_db(_settings):
    await _purge()
    yield
    await _purge()


@pytest.fixture
async def client():
    from app.main import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


def new_email(prefix="user"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}@{DOMAIN}"


async def register(client, email=None, password=PASSWORD, tenant="Acme"):
    email = email or new_email()
    resp = await client.post(
        f"{API}/auth/register", json={"email": email, "password": password, "tenant_name": tenant}
    )
    return email, resp


def bearer(resp):
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


# ---------------------------------------------------------------- registration
async def test_register_then_me(client):
    email, r = await register(client, tenant="  Acme Corp  ")
    assert r.status_code == 201
    assert r.json()["token_type"] == "bearer" and r.json()["expires_in"] == 900
    assert r.headers["cache-control"] == "no-store"
    me = await client.get(f"{API}/me", headers=bearer(r))
    assert me.status_code == 200
    body = me.json()
    assert set(body) == {"user_id", "tenant_id", "email", "tenant_name"}  # nothing secret leaks
    assert body["email"] == email and body["tenant_name"] == "Acme Corp"


async def test_refresh_cookie_flags(client):
    _, r = await register(client)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api/v1/auth" in cookie
    assert "refresh_token=" in cookie


async def test_password_is_stored_hashed(client):
    email, _ = await register(client)
    row = (await _run_sql("SELECT password_hash FROM users WHERE email = :e", e=email)).scalar_one()
    assert row.startswith("$argon2id$") and PASSWORD not in row


async def test_duplicate_email_rejected(client):
    email, r1 = await register(client)
    _, r2 = await register(client, email=email)
    assert r1.status_code == 201 and r2.status_code == 409


async def test_weak_or_invalid_input_rejected(client):
    for password in ["short", "a" * 129, "Password1234"]:
        _, r = await register(client, password=password)
        assert r.status_code == 422, password
    email = new_email()
    _, r = await register(client, email=email, password=email)  # password equals email
    assert r.status_code == 422
    r = await client.post(f"{API}/auth/register", json={"email": "not-an-email", "password": PASSWORD, "tenant_name": "x"})
    assert r.status_code == 422


async def test_unknown_fields_rejected(client):
    r = await client.post(
        f"{API}/auth/register",
        json={"email": new_email(), "password": PASSWORD, "tenant_name": "x", "is_admin": True},
    )
    assert r.status_code == 422
    r = await client.post(
        f"{API}/auth/register",
        json={"email": new_email(), "password": PASSWORD, "tenant_name": "x", "tenant_id": str(uuid.uuid4())},
    )
    assert r.status_code == 422


async def test_email_is_case_insensitive(client):
    email = new_email("MiXed")
    _, r = await register(client, email=email.upper())
    assert r.status_code == 201
    login = await client.post(f"{API}/auth/login", json={"email": email.lower(), "password": PASSWORD})
    assert login.status_code == 200
    me = await client.get(f"{API}/me", headers=bearer(login))
    assert me.json()["email"] == email.lower()


# ---------------------------------------------------------------- login
async def test_login_ok(client):
    email, _ = await register(client)
    r = await client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200 and r.json()["access_token"]


async def test_wrong_password_and_unknown_email_look_identical(client):
    email, _ = await register(client)
    wrong = await client.post(f"{API}/auth/login", json={"email": email, "password": "wrong password here"})
    unknown = await client.post(f"{API}/auth/login", json={"email": new_email(), "password": "wrong password here"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


async def test_overlong_login_password_rejected(client):
    r = await client.post(f"{API}/auth/login", json={"email": new_email(), "password": "a" * 5000})
    assert r.status_code == 422


# ---------------------------------------------------------------- protected endpoint
async def test_me_requires_a_valid_token(client):
    for headers in [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"}, {"Authorization": "Bearer garbage"}]:
        r = await client.get(f"{API}/me", headers=headers)
        assert r.status_code == 401, headers
        assert r.headers["www-authenticate"] == "Bearer"


async def test_expired_token_rejected(client):
    _, r = await register(client)
    me = (await client.get(f"{API}/me", headers=bearer(r))).json()
    expired = security.create_access_token(
        user_id=uuid.UUID(me["user_id"]), tenant_id=uuid.UUID(me["tenant_id"]), secret="t" * 48, ttl_seconds=-60
    )
    r2 = await client.get(f"{API}/me", headers={"Authorization": f"Bearer {expired}"})
    assert r2.status_code == 401


async def test_token_with_someone_elses_tenant_rejected(client):
    _, ra = await register(client, tenant="A")
    _, rb = await register(client, tenant="B")
    a = (await client.get(f"{API}/me", headers=bearer(ra))).json()
    b = (await client.get(f"{API}/me", headers=bearer(rb))).json()
    forged = security.create_access_token(
        user_id=uuid.UUID(a["user_id"]), tenant_id=uuid.UUID(b["tenant_id"]), secret="t" * 48, ttl_seconds=60
    )
    r = await client.get(f"{API}/me", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


async def test_deactivated_user_is_locked_out_immediately(client):
    email, r = await register(client)
    assert (await client.get(f"{API}/me", headers=bearer(r))).status_code == 200
    await _run_sql("UPDATE users SET is_active = false WHERE email = :e", e=email)
    assert (await client.get(f"{API}/me", headers=bearer(r))).status_code == 401
    login = await client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 401


# ---------------------------------------------------------------- refresh and logout
async def test_refresh_rotation_and_reuse_detection(client):
    _, r = await register(client)
    old_cookie = r.cookies.get("refresh_token")
    assert old_cookie

    r2 = await client.post(f"{API}/auth/refresh")  # the cookie jar sends the cookie
    assert r2.status_code == 200
    new_cookie = r2.cookies.get("refresh_token")
    assert new_cookie and new_cookie != old_cookie
    assert (await client.get(f"{API}/me", headers=bearer(r2))).status_code == 200

    # Replaying the OLD token is a theft signal: refused, and every session is ended.
    client.cookies.clear()
    replay = await client.post(f"{API}/auth/refresh", headers={"Cookie": f"refresh_token={old_cookie}"})
    assert replay.status_code == 401
    after = await client.post(f"{API}/auth/refresh", headers={"Cookie": f"refresh_token={new_cookie}"})
    assert after.status_code == 401


async def test_refresh_without_or_with_bad_cookie(client):
    assert (await client.post(f"{API}/auth/refresh")).status_code == 401
    bad = await client.post(f"{API}/auth/refresh", headers={"Cookie": "refresh_token=nonsense"})
    assert bad.status_code == 401


async def test_logout_revokes_the_session(client):
    _, r = await register(client)
    cookie = r.cookies.get("refresh_token")
    out = await client.post(f"{API}/auth/logout")
    assert out.status_code == 204
    client.cookies.clear()
    again = await client.post(f"{API}/auth/refresh", headers={"Cookie": f"refresh_token={cookie}"})
    assert again.status_code == 401


async def test_logout_without_session_is_harmless(client):
    assert (await client.post(f"{API}/auth/logout")).status_code == 204


async def test_audit_log_records_events(client):
    email, r = await register(client)
    await client.post(f"{API}/auth/login", json={"email": email, "password": PASSWORD})
    rows = (await _run_sql(
        "SELECT action FROM audit_log WHERE tenant_id = (SELECT tenant_id FROM users WHERE email = :e) ORDER BY id",
        e=email,
    )).scalars().all()
    assert rows == ["user.registered", "user.login"]
