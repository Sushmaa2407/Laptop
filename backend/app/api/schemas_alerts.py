"""Request and response bodies for alerts."""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_id: uuid.UUID
    flow_id: uuid.UUID | None
    severity: str
    status: str
    evidence: dict
    explanation: dict | None
    explanation_status: str
    created_at: datetime
    decided_at: datetime | None


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["block", "allow", "dismiss"]
    ttl_minutes: Annotated[int, Field(ge=1, le=1440)] = 60  # only used by "block"


class StatsOut(BaseModel):
    open_alerts: int
    alerts_24h: int
    flows_5m: int
    agents_online: int


class CommandOut(BaseModel):
    id: uuid.UUID
    type: str
    ip: str
    ttl_minutes: int | None
    state: str
    result: str | None
    created_at: datetime
    acked_at: datetime | None
