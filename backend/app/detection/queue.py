"""Redis stream that carries flow batches from the API to the detection worker."""

from __future__ import annotations

import json
import os
import uuid

import redis.asyncio as aioredis

FLOW_STREAM = "shield:flows"
FLOW_GROUP = "scorers"
DEAD_LIST = "shield:flows:dead"
ALERT_STREAM = "shield:alerts"  # alert ids waiting for an LLM explanation
STREAM_MAXLEN = 50_000

_client: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(
            os.environ["REDIS_URL"],
            decode_responses=True,
            socket_timeout=30,  # must be longer than the 2 s blocking read in the workers
            socket_connect_timeout=5,
            health_check_interval=30,
        )
    return _client


async def enqueue_flows(tenant_id: uuid.UUID, agent_id: uuid.UUID, flows: list[dict]) -> None:
    payload = json.dumps({"tenant_id": str(tenant_id), "agent_id": str(agent_id), "flows": flows})
    await get_redis().xadd(FLOW_STREAM, {"d": payload}, maxlen=STREAM_MAXLEN, approximate=True)
