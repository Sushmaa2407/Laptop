"""Shared FastAPI dependencies."""

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.repositories import agents as agents_repo
from app.repositories import auth as auth_repo

MAX_CREDENTIAL_LENGTH = 512


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session


@dataclass(frozen=True)
class CurrentUser:
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str


@dataclass(frozen=True)
class CurrentAgent:
    agent_id: uuid.UUID
    tenant_id: uuid.UUID
    name: str


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})


def _bearer_token(request: Request) -> str:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > MAX_CREDENTIAL_LENGTH:
        raise _unauthorized()
    return token


async def get_current_user(request: Request, session: AsyncSession = Depends(get_session)) -> CurrentUser:
    token = _bearer_token(request)
    try:
        claims = security.decode_access_token(token, secret=get_settings().jwt_secret)
    except security.InvalidToken:
        raise _unauthorized() from None
    # The token alone is not enough: the account must still exist, be active,
    # and belong to the tenant named in the token.
    user = await auth_repo.get_user_by_id(session, claims.user_id)
    if user is None or not user.is_active or user.tenant_id != claims.tenant_id:
        raise _unauthorized()
    return CurrentUser(user_id=user.id, tenant_id=user.tenant_id, email=user.email)


async def get_current_agent(request: Request, session: AsyncSession = Depends(get_session)) -> CurrentAgent:
    key = _bearer_token(request)
    if not key.startswith("shk_"):
        raise _unauthorized()
    agent = await agents_repo.get_active_agent_by_key_hash(session, security.hash_token(key))
    if agent is None:
        raise _unauthorized()
    return CurrentAgent(agent_id=agent.id, tenant_id=agent.tenant_id, name=agent.name)
