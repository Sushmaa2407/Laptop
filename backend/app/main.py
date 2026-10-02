import os

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI, Response

app = FastAPI(title="Laptop Shield API")


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
