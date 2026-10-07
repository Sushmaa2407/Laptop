import os
from contextlib import asynccontextmanager

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI, Response

from app.api.auth import me_router
from app.api.auth import router as auth_router
from app.core.config import get_settings
from app.db.session import get_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_settings()  # fail fast if JWT_SECRET is missing or too short
    yield
    await get_engine().dispose()


app = FastAPI(title="Laptop Shield API", lifespan=lifespan)
app.include_router(auth_router, prefix="/api/v1")
app.include_router(me_router, prefix="/api/v1")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/readyz")
async def readyz(response: Response):
    checks = {}
    try:
        conn = await asyncpg.connect(os.environ["DATABASE_URL"], timeout=3)
        await conn.fetchval("SELECT 1")
        await conn.close()
        checks["postgres"] = "ok"
    except Exception:
        checks["postgres"] = "fail"
    try:
        r = aioredis.from_url(os.environ["REDIS_URL"], socket_connect_timeout=3)
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "fail"
    if "fail" in checks.values():
        response.status_code = 503
    return checks
