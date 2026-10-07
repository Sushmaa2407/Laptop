import os
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool


def database_url() -> str:
    """DATABASE_URL from the environment, converted to the asyncpg driver form."""
    url = os.environ["DATABASE_URL"]
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


@lru_cache
def get_engine() -> AsyncEngine:
    if os.environ.get("SHIELD_DB_NULLPOOL") == "1":  # used by tests only
        return create_async_engine(database_url(), poolclass=NullPool)
    return create_async_engine(database_url(), pool_size=5, max_overflow=5, pool_pre_ping=True)


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)
