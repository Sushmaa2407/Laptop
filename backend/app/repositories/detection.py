"""Database writes done by the detection worker. Every function takes tenant_id (tenant-safety rule)."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert, AllowlistEntry, Flow


async def insert_flows(session: AsyncSession, tenant_id: uuid.UUID, agent_id: uuid.UUID, rows: list[dict]) -> None:
    """Store scored flows. A retried batch is ignored (same flow_id), so ingestion is idempotent."""
    if not rows:
        return
    values = [
        {
            **{k: v for k, v in row.items() if k != "start_ts"},
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "start_ts": datetime.fromtimestamp(row["start_ts"], tz=UTC),
        }
        for row in rows
    ]
    stmt = pg_insert(Flow).values(values).on_conflict_do_nothing(index_elements=["tenant_id", "flow_id"])
    await session.execute(stmt)


async def allowlist_cidrs(session: AsyncSession, tenant_id: uuid.UUID) -> list[str]:
    result = await session.execute(select(AllowlistEntry.cidr).where(AllowlistEntry.tenant_id == tenant_id))
    return [str(c) for c in result.scalars().all()]


def add_alert(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    alert_id: uuid.UUID,
    agent_id: uuid.UUID,
    flow_id: uuid.UUID,
    severity: str,
    dedupe_key: str,
    evidence: dict,
) -> Alert:
    alert = Alert(
        id=alert_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        flow_id=flow_id,
        severity=severity,
        dedupe_key=dedupe_key,
        evidence=evidence,
    )
    session.add(alert)
    return alert
