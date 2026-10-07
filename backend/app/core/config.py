"""Settings read from environment variables. The app refuses to start with a weak secret."""
import os
from dataclasses import dataclass
from functools import lru_cache

MIN_SECRET_LENGTH = 32


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    access_token_minutes: int = 15
    refresh_token_days: int = 14
    cookie_secure: bool = True
    rate_limit_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    secret = os.environ.get("JWT_SECRET", "")
    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"JWT_SECRET must be set and at least {MIN_SECRET_LENGTH} characters long")
    return Settings(
        jwt_secret=secret,
        access_token_minutes=int(os.environ.get("ACCESS_TOKEN_MINUTES", "15")),
        refresh_token_days=int(os.environ.get("REFRESH_TOKEN_DAYS", "14")),
        cookie_secure=os.environ.get("COOKIE_SECURE", "true").lower() != "false",
        rate_limit_enabled=os.environ.get("RATE_LIMIT_ENABLED", "true").lower() != "false",
    )
