"""Alerts for logged-in users: list, inspect, decide (block / allow / dismiss), and dashboard counters."""

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user, get_session
from app.detection.evidence import offender_ip
from app.api.schemas_alerts import AlertOut, CommandOut, DecisionBody, StatsOut
from app.repositories import alerts as alerts_repo
from app.repositories import auth as auth_repo
from app.repositories import commands as commands_repo

router = APIRouter(tags=["alerts"])

_STATUS_FOR_ACTION = {"block": "blocked", "allow": "allowed", "dismiss": "dismissed"}


@router.get("/alerts", response_model=list[AlertOut])
async def list_alerts(
    status: Literal["open", "allowed", "blocked", "dismissed", "expired"] | None = None,
    limit: int = Query(50, ge=1, le=200),
    current: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    return await alerts_repo.list_alerts(session, current.tenant_id, status=status, limit=limit)


@router.get("/alerts/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: uuid.UUID, current: CurrentUser = Depends(get_current_user), session: AsyncSession = Depends(get_session)
):
    alert = await alerts_repo.get_alert(session, current.tenant_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/alerts/{alert_id}/decision", response_model=AlertOut)
async def decide_alert(
    alert_id: uuid.UUID,
    body: DecisionBody,
    current: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    alert = await alerts_repo.get_alert(session, current.tenant_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status != "open":
        raise HTTPException(status_code=409, detail=f"Alert already {alert.status}")
    src_ip = offender_ip(alert.evidence)
    if body.action == "block":
        commands_repo.add_command(
            session, current.tenant_id, agent_id=alert.agent_id, alert_id=alert.id,
            type="block_ip", ip=src_ip, ttl_minutes=body.ttl_minutes,
        )
    elif body.action == "allow":
        await alerts_repo.allow_ip(session, current.tenant_id, src_ip, note=f"allowed from alert {alert.id}")
    await alerts_repo.decide(session, current.tenant_id, alert, status=_STATUS_FOR_ACTION[body.action],
                             user_id=current.user_id)
    auth_repo.audit(session, current.tenant_id, str(current.user_id), f"alert.{body.action}", str(alert.id))
    await session.commit()
    await session.refresh(alert)
    return alert


@router.get("/stats", response_model=StatsOut)
async def stats(current: CurrentUser = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    return await alerts_repo.stats(session, current.tenant_id)


@router.get("/alerts/{alert_id}/commands", response_model=list[CommandOut])
async def alert_commands(
    alert_id: uuid.UUID, current: CurrentUser = Depends(get_current_user), session: AsyncSession = Depends(get_session)
):
    """What was sent to the agent because of this alert, and whether the agent confirmed it."""
    if await alerts_repo.get_alert(session, current.tenant_id, alert_id) is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    rows = await commands_repo.list_for_alert(session, current.tenant_id, alert_id)
    return [CommandOut(id=r.id, type=r.type, ip=str(r.ip).split("/")[0], ttl_minutes=r.ttl_minutes, state=r.state,
                       result=r.result, created_at=r.created_at, acked_at=r.acked_at) for r in rows]


@router.post("/alerts/{alert_id}/unblock", response_model=AlertOut)
async def unblock_alert(
    alert_id: uuid.UUID, current: CurrentUser = Depends(get_current_user), session: AsyncSession = Depends(get_session)
):
    """Lift a block early. The agent removes the firewall rule on its next poll; the alert moves to "dismissed"."""
    alert = await alerts_repo.get_alert(session, current.tenant_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status != "blocked":
        raise HTTPException(status_code=409, detail="Alert is not blocked")
    commands_repo.add_command(
        session, current.tenant_id, agent_id=alert.agent_id, alert_id=alert.id,
        type="unblock_ip", ip=offender_ip(alert.evidence), ttl_minutes=None,
    )
    await alerts_repo.decide(session, current.tenant_id, alert, status="dismissed", user_id=current.user_id)
    auth_repo.audit(session, current.tenant_id, str(current.user_id), "alert.unblock", str(alert.id))
    await session.commit()
    await session.refresh(alert)
    return alert
