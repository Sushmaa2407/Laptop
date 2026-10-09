import asyncio
import time
import uuid

import jwt
import pytest

from app.core import security
from app.core.config import get_settings

SECRET = "s" * 40


def make_token(drop=(), **over):
    now = int(time.time())
    payload = {
        "sub": str(uuid.uuid4()),
        "tid": str(uuid.uuid4()),
        "typ": "access",
        "iat": now,
        "exp": now + 60,
        "jti": "abc123",
    }
    payload.update(over)
    for key in drop:
        payload.pop(key, None)
    return jwt.encode(payload, SECRET, algorithm="HS256")


# ---- passwords
def test_password_policy():
    security.validate_password_policy("correct horse battery")
    for bad in ["short", " " * 20, "a" * 129, "Password1234", "123456789012"]:
        with pytest.raises(ValueError):
            security.validate_password_policy(bad)


def test_hash_and_verify():
    h = security.hash_password_sync("correct horse battery")
    assert h.startswith("$argon2id$")
    assert security.verify_password_sync(h, "correct horse battery") is True
    assert security.verify_password_sync(h, "wrong password here") is False


def test_hashes_are_salted():
    a = security.hash_password_sync("same password 123")
    b = security.hash_password_sync("same password 123")
    assert a != b


def test_corrupt_hash_is_a_failed_login_not_a_crash():
    assert security.verify_password_sync("not-a-hash", "whatever") is False
    assert security.verify_password_sync("", "whatever") is False


def test_async_wrappers():
    async def go():
        h = await security.hash_password("correct horse battery")
        assert await security.verify_password(h, "correct horse battery")
        assert not await security.verify_password(h, "nope nope nope nope")
        await security.verify_unknown_user("anything")

    asyncio.run(go())


# ---- access tokens
def test_access_token_roundtrip():
    uid, tid = uuid.uuid4(), uuid.uuid4()
    token = security.create_access_token(user_id=uid, tenant_id=tid, secret=SECRET, ttl_seconds=60)
    claims = security.decode_access_token(token, secret=SECRET)
    assert claims.user_id == uid and claims.tenant_id == tid
    assert len(claims.jti) >= 16


def test_expired_token_rejected():
    token = security.create_access_token(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), secret=SECRET, ttl_seconds=-60)
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(token, secret=SECRET)


def test_wrong_secret_rejected():
    token = make_token()
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(token, secret="o" * 40)


def test_tampered_payload_rejected():
    head, _, sig = make_token().split(".")
    other_payload = make_token().split(".")[1]
    forged = ".".join([head, other_payload, sig])
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(forged, secret=SECRET)


def test_alg_none_rejected():
    now = int(time.time())
    payload = {
        "sub": str(uuid.uuid4()),
        "tid": str(uuid.uuid4()),
        "typ": "access",
        "iat": now,
        "exp": now + 60,
        "jti": "abc123",
    }
    token = jwt.encode(payload, None, algorithm="none")
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(token, secret=SECRET)


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "tid", "jti"])
def test_missing_claims_rejected(missing):
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(make_token(drop=(missing,)), secret=SECRET)


def test_wrong_type_and_bad_subject_rejected():
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(make_token(typ="refresh"), secret=SECRET)
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(make_token(sub="not-a-uuid"), secret=SECRET)


@pytest.mark.parametrize("junk", ["", "abc", "a.b.c", None])
def test_junk_rejected(junk):
    with pytest.raises(security.InvalidToken):
        security.decode_access_token(junk, secret=SECRET)  # type: ignore[arg-type]


def test_short_signing_secret_refused():
    with pytest.raises(ValueError):
        security.create_access_token(user_id=uuid.uuid4(), tenant_id=uuid.uuid4(), secret="short", ttl_seconds=60)


# ---- opaque tokens
def test_opaque_tokens():
    t1, h1 = security.new_opaque_token()
    t2, h2 = security.new_opaque_token()
    assert t1 != t2 and h1 != h2
    assert h1 == security.hash_token(t1)
    assert len(h1) == 64 and t1 != h1 and len(t1) >= 40


# ---- settings
def test_settings_require_a_strong_secret(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        get_settings()
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(RuntimeError):
        get_settings()
    monkeypatch.setenv("JWT_SECRET", "y" * 32)
    settings = get_settings()
    assert settings.access_token_minutes == 15 and settings.cookie_secure is True
    get_settings.cache_clear()


def test_api_keys_and_enrollment_codes():
    key, key_hash = security.new_api_key()
    assert key.startswith("shk_") and len(key) >= 40
    assert key_hash == security.hash_token(key) and len(key_hash) == 64
    assert security.new_api_key()[0] != key
    code, code_hash = security.new_enrollment_code()
    assert len(code) >= 16 and code_hash == security.hash_token(code)
