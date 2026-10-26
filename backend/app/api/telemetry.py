"""Agent-facing endpoints: send flows, fetch commands, report command results."""

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentAgent, get_current_agent, get_session
from app.detection import queue
from app.repositories import commands as commands_repo
from shield_common.schemas import Command, TelemetryBatch

router = APIRouter(prefix="/agent", tags=["agent"])


class AckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: Literal["applied", "failed", "expired", "reverted"]
    result: str = Field(default="", max_length=200)


@router.post("/telemetry", status_code=202)
async def telemetry(body: TelemetryBatch, agent: CurrentAgent = Depends(get_current_agent)):
    """Accept a batch of flows. They are validated here, scored and stored by the worker."""
    flows = [f.model_dump(mode="json") for f in body.flows]
    try:
        await queue.enqueue_flows(agent.tenant_id, agent.agent_id, flows)
    except RedisError:
        raise HTTPException(status_code=503, detail="Ingestion queue unavailable") from None
    return {"accepted": len(flows)}


@router.get("/commands", response_model=list[Command], response_model_exclude_none=True)
async def pending_commands(agent: CurrentAgent = Depends(get_current_agent), session: AsyncSession = Depends(get_session)):
    rows = await commands_repo.list_pending(session, agent.tenant_id, agent.agent_id)
    return [
        Command(command_id=r.id, type=r.type, ip=str(r.ip).split("/")[0], ttl_minutes=r.ttl_minutes) for r in rows
    ]


@router.post("/commands/{command_id}/ack", status_code=204)
async def ack_command(
    command_id: uuid.UUID,
    body: AckBody,
    agent: CurrentAgent = Depends(get_current_agent),
    session: AsyncSession = Depends(get_session),
):
    ok = await commands_repo.acknowledge(
        session, agent.tenant_id, agent.agent_id, command_id, state=body.state, result=body.result
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Command not found")
    await session.commit()
