"""Commands the server sends to agents (block / unblock an IP). Every function takes tenant_id."""

import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AgentCommand

STALE_AFTER_MINUTES = 10  # a command the agent never picked up within this time is no longer sent

# which states each new state may be reached from
_ALLOWED_FROM = {
    "applied": ("pending",),
    "failed": ("pending",),
    "expired": ("applied",),
    "reverted": ("applied",),
}


def add_command(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    agent_id: uuid.UUID,
    alert_id: uuid.UUID | None,
    type: str,
    ip: str,
    ttl_minutes: int | None,
) -> AgentCommand:
    cmd = AgentCommand(tenant_id=tenant_id, agent_id=agent_id, alert_id=alert_id, type=type, ip=ip,
                       ttl_minutes=ttl_minutes)
    session.add(cmd)
    return cmd


async def list_pending(session: AsyncSession, tenant_id: uuid.UUID, agent_id: uuid.UUID) -> list[AgentCommand]:
    from sqlalchemy import func, text

    result = await session.execute(
        select(AgentCommand)
        .where(
            AgentCommand.tenant_id == tenant_id,
            AgentCommand.agent_id == agent_id,
            AgentCommand.state == "pending",
            AgentCommand.created_at > func.now() - text(f"interval '{STALE_AFTER_MINUTES} minutes'"),
        )
        .order_by(AgentCommand.created_at)
        .limit(20)
    )
    return list(result.scalars().all())


async def acknowledge(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    command_id: uuid.UUID,
    *,
    state: str,
    result: str,
) -> bool:
    """Record the agent's report. False if the command is not this agent's or the change is not allowed."""
    from sqlalchemy import func

    stmt = (
        update(AgentCommand)
        .where(
            AgentCommand.tenant_id == tenant_id,
            AgentCommand.agent_id == agent_id,
            AgentCommand.id == command_id,
            AgentCommand.state.in_(_ALLOWED_FROM[state]),
        )
        .values(state=state, result=result[:200], acked_at=func.now())
        .returning(AgentCommand.id)
        .execution_options(synchronize_session=False)
    )
    return (await session.execute(stmt)).first() is not None


async def list_for_alert(session: AsyncSession, tenant_id: uuid.UUID, alert_id: uuid.UUID) -> list[AgentCommand]:
    result = await session.execute(
        select(AgentCommand)
        .where(AgentCommand.tenant_id == tenant_id, AgentCommand.alert_id == alert_id)
        .order_by(AgentCommand.created_at.desc())
        .limit(10)
    )
    return list(result.scalars().all())
