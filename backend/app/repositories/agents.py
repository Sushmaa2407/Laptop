"""Agents and enrollment codes.

Every function takes tenant_id, EXCEPT the two that authenticate a secret
(consume_enrollment_code and get_active_agent_by_key_hash): there the secret identifies the tenant.
tests/test_schema_rules.py enforces this rule for every public function in this module.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Agent, EnrollmentCode


def add_enrollment_code(
    session: AsyncSession, tenant_id: uuid.UUID, *, agent_name: str, code_hash: str, expires_at: datetime
) -> None:
    session.add(EnrollmentCode(tenant_id=tenant_id, agent_name=agent_name, code_hash=code_hash, expires_at=expires_at))


async def consume_enrollment_code(session: AsyncSession, code_hash: str):
    """Atomically mark a valid, unused, unexpired code as used. Single use even under concurrency.

    Returns a row (tenant_id, agent_name) or None.
    """
    stmt = (
        update(EnrollmentCode)
        .where(
            EnrollmentCode.code_hash == code_hash,
            EnrollmentCode.used_at.is_(None),
            EnrollmentCode.expires_at > func.now(),
        )
        .values(used_at=func.now())
        .returning(EnrollmentCode.tenant_id, EnrollmentCode.agent_name)
        .execution_options(synchronize_session=False)
    )
    return (await session.execute(stmt)).one_or_none()


async def create_agent(
    session: AsyncSession, tenant_id: uuid.UUID, *, name: str, api_key_hash: str, platform: str, version: str
) -> Agent:
    agent = Agent(tenant_id=tenant_id, name=name, api_key_hash=api_key_hash, platform=platform, version=version)
    session.add(agent)
    await session.flush()
    return agent


async def list_agents(session: AsyncSession, tenant_id: uuid.UUID) -> list[Agent]:
    result = await session.execute(
        select(Agent).where(Agent.tenant_id == tenant_id).order_by(Agent.created_at, Agent.id)
    )
    return list(result.scalars().all())


async def get_agent(session: AsyncSession, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> Agent | None:
    result = await session.execute(select(Agent).where(Agent.tenant_id == tenant_id, Agent.id == agent_id))
    return result.scalar_one_or_none()


async def revoke_agent(session: AsyncSession, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> bool:
    """Revoke an agent of this tenant. False if it does not exist for this tenant. Idempotent."""
    agent = await get_agent(session, tenant_id, agent_id)
    if agent is None:
        return False
    if agent.status != "revoked":
        agent.status = "revoked"
        agent.revoked_at = datetime.now(UTC)
    return True


async def touch_agent(
    session: AsyncSession, tenant_id: uuid.UUID, agent_id: uuid.UUID, *, platform: str, version: str
) -> None:
    await session.execute(
        update(Agent)
        .where(Agent.tenant_id == tenant_id, Agent.id == agent_id)
        .values(last_seen_at=func.now(), platform=platform, version=version)
        .execution_options(synchronize_session=False)
    )


async def get_active_agent_by_key_hash(session: AsyncSession, key_hash: str) -> Agent | None:
    result = await session.execute(select(Agent).where(Agent.api_key_hash == key_hash, Agent.status == "active"))
    return result.scalar_one_or_none()
