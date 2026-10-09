"""Short-lived Redis connections for the auth endpoints (ingestion will keep a long-lived client)."""

import os
from contextlib import asynccontextmanager

import redis.asyncio as aioredis


@asynccontextmanager
async def redis_client():
    client = aioredis.from_url(
        os.environ["REDIS_URL"], decode_responses=True, socket_connect_timeout=2, socket_timeout=2
    )
    try:
        yield client
    finally:
        await client.aclose()
