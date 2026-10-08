"""Request and response bodies for agents and enrollment."""
import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

from shield_common.schemas import VersionStr


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


AgentName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]


class EnrollmentCodeCreate(_Strict):
    agent_name: AgentName


class EnrollmentCodeResponse(BaseModel):
    code: str
    agent_name: str
    expires_at: datetime


class EnrollRequest(_Strict):
    code: Annotated[str, StringConstraints(strip_whitespace=True, min_length=8, max_length=64)]
    platform: Literal["linux", "windows", "other"]
    version: VersionStr


class EnrollResponse(BaseModel):
    agent_id: uuid.UUID
    api_key: str
    agent_name: str


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    platform: str | None
    version: str | None
    status: str
    last_seen_at: datetime | None
    created_at: datetime
