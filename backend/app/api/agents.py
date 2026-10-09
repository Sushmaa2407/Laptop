"""Agent management (for logged-in users) and the agent-facing endpoints (enroll, heartbeat)."""

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentAgent, CurrentUser, get_current_agent, get_current_user, get_session
from app.api.schemas_agents import (
    AgentOut,
    EnrollmentCodeCreate,
    EnrollmentCodeResponse,
    EnrollRequest,
    EnrollResponse,
)
from app.core import ratelimit, security
from app.repositories import agents as agents_repo
from app.repositories import auth as auth_repo
from shield_common.schemas import Heartbeat

ENROLLMENT_CODE_MINUTES = 15

router = APIRouter(prefix="/agents", tags=["agents"])
agent_router = APIRouter(prefix="/agent", tags=["agent"])


def _agent_not_found() -> HTTPException:
    # Same answer for "does not exist" and "belongs to another tenant": nothing leaks.
    return HTTPException(status_code=404, detail="Agent not found")


# ---------------------------------------------------------------- for logged-in users
@router.post("/enrollment-codes", response_model=EnrollmentCodeResponse, status_code=201)
async def create_enrollment_code(
    body: EnrollmentCodeCreate,
    response: Response,
    current: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    await ratelimit.hit(ratelimit.ENROLL_CODES_PER_TENANT, str(current.tenant_id))
    code, code_hash = security.new_enrollment_code()
    expires_at = auth_repo.utcnow() + timedelta(minutes=ENROLLMENT_CODE_MINUTES)
    agents_repo.add_enrollment_code(
        session, current.tenant_id, agent_name=body.agent_name, code_hash=code_hash, expires_at=expires_at
    )
    auth_repo.audit(session, current.tenant_id, str(current.user_id), "agent.enrollment_code_created", body.agent_name)
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    return EnrollmentCodeResponse(code=code, agent_name=body.agent_name, expires_at=expires_at)


@router.get("", response_model=list[AgentOut])
async def list_agents(current: CurrentUser = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    return await agents_repo.list_agents(session, current.tenant_id)


@router.get("/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: uuid.UUID,
    current: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    agent = await agents_repo.get_agent(session, current.tenant_id, agent_id)
    if agent is None:
        raise _agent_not_found()
    return agent


@router.delete("/{agent_id}", status_code=204)
async def revoke_agent(
    agent_id: uuid.UUID,
    current: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not await agents_repo.revoke_agent(session, current.tenant_id, agent_id):
        raise _agent_not_found()
    auth_repo.audit(session, current.tenant_id, str(current.user_id), "agent.revoked", str(agent_id))
    await session.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------- for agents
@agent_router.post("/enroll", response_model=EnrollResponse, status_code=201)
async def enroll(
    body: EnrollRequest, request: Request, response: Response, session: AsyncSession = Depends(get_session)
):
    await ratelimit.hit(ratelimit.ENROLL_PER_IP, ratelimit.client_ip(request))
    row = await agents_repo.consume_enrollment_code(session, security.hash_token(body.code))
    if row is None:  # unknown, expired and already-used codes look identical
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment code")
    api_key, key_hash = security.new_api_key()
    agent = await agents_repo.create_agent(
        session,
        row.tenant_id,
        name=row.agent_name,
        api_key_hash=key_hash,
        platform=body.platform,
        version=body.version,
    )
    auth_repo.audit(session, row.tenant_id, f"agent:{agent.id}", "agent.enrolled", str(agent.id))
    await session.commit()  # marking the code used and creating the agent succeed or fail together
    response.headers["Cache-Control"] = "no-store"
    return EnrollResponse(agent_id=agent.id, api_key=api_key, agent_name=agent.name)


@agent_router.post("/heartbeat", status_code=204)
async def heartbeat(
    body: Heartbeat,
    agent: CurrentAgent = Depends(get_current_agent),
    session: AsyncSession = Depends(get_session),
):
    await ratelimit.hit(ratelimit.HEARTBEAT_PER_AGENT, str(agent.agent_id))
    await agents_repo.touch_agent(
        session, agent.tenant_id, agent.agent_id, platform=body.platform, version=body.agent_version
    )
    await session.commit()
    return Response(status_code=204)
