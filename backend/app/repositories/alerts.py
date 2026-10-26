"""Alerts as seen by logged-in users. Every function takes tenant_id."""

import uuid

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Agent, Alert, AllowlistEntry, Flow


async def list_alerts(session: AsyncSession, tenant_id: uuid.UUID, *, status: str | None, limit: int) -> list[Alert]:
    stmt = select(Alert).where(Alert.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(Alert.status == status)
    stmt = stmt.order_by(Alert.created_at.desc(), Alert.id).limit(limit)
    return list((await session.execute(stmt)).scalars().all())


async def get_alert(session: AsyncSession, tenant_id: uuid.UUID, alert_id: uuid.UUID) -> Alert | None:
    result = await session.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.id == alert_id))
    return result.scalar_one_or_none()


async def decide(
    session: AsyncSession, tenant_id: uuid.UUID, alert: Alert, *, status: str, user_id: uuid.UUID
) -> None:
    alert.status = status
    alert.decided_by = user_id
    alert.decided_at = func.now()


async def allow_ip(session: AsyncSession, tenant_id: uuid.UUID, ip: str, note: str) -> None:
    """Trust this address from now on (a /32 or /128 allowlist entry)."""
    cidr = f"{ip}/{128 if ':' in ip else 32}"
    stmt = (
        pg_insert(AllowlistEntry)
        .values(tenant_id=tenant_id, cidr=cidr, note=note[:200])
        .on_conflict_do_nothing(constraint="uq_allowlist_tenant_cidr")
    )
    await session.execute(stmt)


async def stats(session: AsyncSession, tenant_id: uuid.UUID) -> dict[str, int]:
    open_alerts = await session.scalar(
        select(func.count()).select_from(Alert).where(Alert.tenant_id == tenant_id, Alert.status == "open")
    )
    alerts_24h = await session.scalar(
        select(func.count())
        .select_from(Alert)
        .where(Alert.tenant_id == tenant_id, Alert.created_at > func.now() - text("interval '24 hours'"))
    )
    flows_5m = await session.scalar(
        select(func.count())
        .select_from(Flow)
        .where(Flow.tenant_id == tenant_id, Flow.received_at > func.now() - text("interval '5 minutes'"))
    )
    agents_online = await session.scalar(
        select(func.count())
        .select_from(Agent)
        .where(
            Agent.tenant_id == tenant_id,
            Agent.status == "active",
            Agent.last_seen_at > func.now() - text("interval '60 seconds'"),
        )
    )
    return {
        "open_alerts": open_alerts or 0,
        "alerts_24h": alerts_24h or 0,
        "flows_5m": flows_5m or 0,
        "agents_online": agents_online or 0,
    }


async def set_explanation(
    session: AsyncSession, tenant_id: uuid.UUID, alert_id: uuid.UUID, *, explanation: dict, status: str
) -> bool:
    """Store an explanation ('ready' = written by the LLM, 'fallback' = from the template). Only if still pending."""
    from sqlalchemy import update

    result = await session.execute(
        update(Alert)
        .where(Alert.tenant_id == tenant_id, Alert.id == alert_id, Alert.explanation_status == "pending")
        .values(explanation=explanation, explanation_status=status)
        .returning(Alert.id)
    )
    return result.first() is not None
