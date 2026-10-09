"""Password hashing, access tokens and opaque tokens. No database access in this module."""

import asyncio
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MIN_SECRET_LENGTH = 32
JWT_ALGORITHM = "HS256"

_COMMON_PASSWORDS = {
    "password1234",
    "123456789012",
    "qwertyuiop12",
    "iloveyou1234",
    "administrator",
    "letmein123456",
    "welcome12345",
}

_hasher = PasswordHasher()  # Argon2id with the library's recommended parameters
# A real hash of a random password: lets "unknown email" take as long as "wrong password".
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


# ---------------------------------------------------------------- passwords
def validate_password_policy(password: str) -> None:
    """Length-based policy (no silly composition rules). Raises ValueError with a safe message."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    if not password.strip():
        raise ValueError("password must not be only spaces")
    if password.lower() in _COMMON_PASSWORDS:
        raise ValueError("password is too common")


def hash_password_sync(password: str) -> str:
    return _hasher.hash(password)


def verify_password_sync(password_hash: str, password: str) -> bool:
    """True only if the password matches. A bad or corrupt hash counts as a failed login."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(hash_password_sync, password)


async def verify_password(password_hash: str, password: str) -> bool:
    return await asyncio.to_thread(verify_password_sync, password_hash, password)


async def verify_unknown_user(password: str) -> None:
    """Spend the time of a real check so response time does not reveal whether an email exists."""
    await asyncio.to_thread(verify_password_sync, _DUMMY_HASH, password)


# ---------------------------------------------------------------- access tokens (JWT)
class InvalidToken(Exception):
    """The token is missing, expired, forged or malformed."""


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    jti: str
    expires_at: int


def create_access_token(*, user_id: uuid.UUID, tenant_id: uuid.UUID, secret: str, ttl_seconds: int) -> str:
    if len(secret) < MIN_SECRET_LENGTH:
        raise ValueError("signing secret is too short")
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "typ": "access",
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str, *, secret: str) -> AccessClaims:
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],  # fixed list: "none" and other algorithms are refused
            options={"require": ["exp", "iat", "sub", "tid", "jti"]},
            leeway=5,
        )
        if payload.get("typ") != "access":
            raise InvalidToken("wrong token type")
        return AccessClaims(
            user_id=uuid.UUID(payload["sub"]),
            tenant_id=uuid.UUID(payload["tid"]),
            jti=str(payload["jti"]),
            expires_at=int(payload["exp"]),
        )
    except InvalidToken:
        raise
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise InvalidToken("invalid token") from exc


# ---------------------------------------------------------------- opaque tokens (refresh tokens, later API keys)
def hash_token(token: str) -> str:
    """SHA-256 of a high-entropy random token. The database stores this, never the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_opaque_token() -> tuple[str, str]:
    """Return (token to give to the client, hash to store in the database)."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def new_api_key() -> tuple[str, str]:
    """Return (agent API key to show once, hash to store). Keys start with shk_ so they are easy to spot."""
    key = "shk_" + secrets.token_urlsafe(32)
    return key, hash_token(key)


def new_enrollment_code() -> tuple[str, str]:
    """Return (one-time enrollment code to show once, hash to store)."""
    code = secrets.token_urlsafe(12)
    return code, hash_token(code)
