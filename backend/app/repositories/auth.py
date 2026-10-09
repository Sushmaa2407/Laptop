"""All database access for users, tenants and refresh tokens."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, RefreshToken, Tenant, User


class EmailTaken(Exception):
    pass


def utcnow() -> datetime:
    return datetime.now(UTC)


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    return (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()


async def get_user_by_id(session: AsyncSession, user_id: uuid.UUID) -> User | None:
    return (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()


async def get_tenant(session: AsyncSession, tenant_id: uuid.UUID) -> Tenant | None:
    return (await session.execute(select(Tenant).where(Tenant.id == tenant_id))).scalar_one_or_none()


def audit(session: AsyncSession, tenant_id: uuid.UUID, actor: str, action: str, target: str | None = None) -> None:
    session.add(AuditLog(tenant_id=tenant_id, actor=actor, action=action, target=target))


async def create_tenant_and_user(session: AsyncSession, *, tenant_name: str, email: str, password_hash: str) -> User:
    tenant = Tenant(name=tenant_name)
    session.add(tenant)
    await session.flush()
    user = User(tenant_id=tenant.id, email=email, password_hash=password_hash)
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:  # the unique constraint on email is the source of truth
        await session.rollback()
        raise EmailTaken from exc
    audit(session, tenant.id, str(user.id), "user.registered", str(user.id))
    return user


def add_refresh_token(session: AsyncSession, *, user_id: uuid.UUID, token_hash: str, ttl_days: int) -> None:
    session.add(RefreshToken(user_id=user_id, token_hash=token_hash, expires_at=utcnow() + timedelta(days=ttl_days)))


async def get_refresh_token(session: AsyncSession, token_hash: str, *, for_update: bool = False) -> RefreshToken | None:
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    if for_update:
        stmt = stmt.with_for_update()  # stops two simultaneous refreshes both succeeding
    return (await session.execute(stmt)).scalar_one_or_none()


async def revoke_all_for_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
