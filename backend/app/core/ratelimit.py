"""Redis-backed rate limiting. Keys hold only hashes, never raw emails or IP addresses.

If Redis is unavailable we fail CLOSED (503): losing the protection silently would be worse.
"""
import hashlib
from dataclasses import dataclass

from fastapi import HTTPException, Request

from app.core.config import get_settings
from app.core.redis_client import redis_client

# Atomic: count the event and make sure the counter always expires.
_INCR_SCRIPT = """
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then redis.call('EXPIRE', KEYS[1], ARGV[1]); ttl = tonumber(ARGV[1]) end
return {c, ttl}
"""


@dataclass(frozen=True)
class Limit:
    name: str
    max_events: int
    window_seconds: int


LOGIN_PER_IP = Limit("login_ip", 30, 900)
LOGIN_FAILS_PER_IP_EMAIL = Limit("login_fail_ip_email", 5, 900)
LOGIN_FAILS_PER_EMAIL = Limit("login_fail_email", 30, 3600)
REGISTER_PER_IP = Limit("register_ip", 5, 3600)
REFRESH_PER_IP = Limit("refresh_ip", 120, 900)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _key(limit: Limit, parts: tuple[str, ...]) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"rl:{limit.name}:{digest}"


def _unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="Service temporarily unavailable")


def _too_many(ttl: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail="Too many attempts. Try again later.",
        headers={"Retry-After": str(max(int(ttl), 1))},
    )


async def _incr(limit: Limit, parts: tuple[str, ...]) -> tuple[int, int]:
    try:
        async with redis_client() as r:
            count, ttl = await r.eval(_INCR_SCRIPT, 1, _key(limit, parts), limit.window_seconds)
    except Exception:
        raise _unavailable() from None
    return int(count), int(ttl)


async def hit(limit: Limit, *parts: str) -> None:
    """Count one event and refuse (429) once the limit is exceeded."""
    if not get_settings().rate_limit_enabled:
        return
    count, ttl = await _incr(limit, parts)
    if count > limit.max_events:
        raise _too_many(ttl)


async def record(limit: Limit, *parts: str) -> None:
    """Count one event without refusing (used for failed logins)."""
    if not get_settings().rate_limit_enabled:
        return
    await _incr(limit, parts)


async def check(limit: Limit, *parts: str) -> None:
    """Refuse (429) if the limit has already been reached, without counting."""
    if not get_settings().rate_limit_enabled:
        return
    try:
        async with redis_client() as r:
            key = _key(limit, parts)
            count = await r.get(key)
            ttl = await r.ttl(key) if count is not None else 0
    except Exception:
        raise _unavailable() from None
    if count is not None and int(count) >= limit.max_events:
        raise _too_many(ttl)


async def reset(limit: Limit, *parts: str) -> None:
    if not get_settings().rate_limit_enabled:
        return
    try:
        async with redis_client() as r:
            await r.delete(_key(limit, parts))
    except Exception:
        raise _unavailable() from None
