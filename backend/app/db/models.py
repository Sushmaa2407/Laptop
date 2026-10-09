"""Database tables (SQLAlchemy 2.0).

Tenant safety built into the schema:
- Every table except `tenants` carries tenant_id.
- Rows that point at an agent, user or alert use COMPOSITE foreign keys that include
  tenant_id, so the database refuses to link rows that belong to different tenants.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


def uuid_pk():
    return mapped_column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())


def now_col():
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def tenant_fk_col():
    return mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = now_col()


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_users_tenant_id_id"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
    )
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk_col()
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"), nullable=False)
    created_at: Mapped[datetime] = now_col()


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = now_col()


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_agents_tenant_id_id"),
        CheckConstraint("status IN ('active', 'revoked')", name="status_valid"),
    )
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk_col()
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    platform: Mapped[str | None] = mapped_column(String(16))
    version: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), server_default="active", nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = now_col()


class EnrollmentCode(Base):
    __tablename__ = "enrollment_codes"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk_col()
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = now_col()


class Flow(Base):
    __tablename__ = "flows"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "agent_id"], ["agents.tenant_id", "agents.id"], ondelete="CASCADE"),
        CheckConstraint("protocol IN ('tcp', 'udp', 'icmp', 'other')", name="protocol_valid"),
        CheckConstraint("src_port BETWEEN 0 AND 65535 AND dst_port BETWEEN 0 AND 65535", name="ports_valid"),
        Index("ix_flows_tenant_start", "tenant_id", "start_ts"),
    )
    # Composite primary key: a tenant can never collide with another tenant's flow ids.
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    flow_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    start_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    dst_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int] = mapped_column(Integer, nullable=False)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    duration_s: Mapped[float] = mapped_column(Float, nullable=False)
    fwd_packets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    bwd_packets: Mapped[int] = mapped_column(BigInteger, nullable=False)
    fwd_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    bwd_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    pkt_len_mean: Mapped[float] = mapped_column(Float, nullable=False)
    pkt_len_std: Mapped[float] = mapped_column(Float, nullable=False)
    iat_mean_s: Mapped[float] = mapped_column(Float, nullable=False)
    syn_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    rst_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    fin_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    uniq_dst_ports_60s: Mapped[int] = mapped_column(BigInteger, nullable=False)
    uniq_dst_ips_60s: Mapped[int] = mapped_column(BigInteger, nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    received_at: Mapped[datetime] = now_col()


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_alerts_tenant_id_id"),
        ForeignKeyConstraint(["tenant_id", "agent_id"], ["agents.tenant_id", "agents.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "decided_by"], ["users.tenant_id", "users.id"]),
        CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name="severity_valid"),
        CheckConstraint("status IN ('open', 'allowed', 'blocked', 'dismissed', 'expired')", name="status_valid"),
        CheckConstraint("explanation_status IN ('pending', 'ready', 'fallback')", name="explanation_status_valid"),
        Index("ix_alerts_tenant_created", "tenant_id", "created_at", "id"),
        Index("ix_alerts_tenant_dedupe", "tenant_id", "dedupe_key", "created_at"),
    )
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    flow_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))  # flows expire; no FK
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), server_default="open", nullable=False)
    dedupe_key: Mapped[str | None] = mapped_column(String(200))
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    explanation: Mapped[dict | None] = mapped_column(JSONB)
    explanation_status: Mapped[str] = mapped_column(String(16), server_default="pending", nullable=False)
    created_at: Mapped[datetime] = now_col()
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class AgentCommand(Base):
    __tablename__ = "commands"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "agent_id"], ["agents.tenant_id", "agents.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "alert_id"], ["alerts.tenant_id", "alerts.id"], ondelete="CASCADE"),
        CheckConstraint("type IN ('block_ip', 'unblock_ip')", name="type_valid"),
        CheckConstraint("state IN ('pending', 'applied', 'failed', 'expired', 'reverted')", name="state_valid"),
        CheckConstraint(
            "(type = 'block_ip' AND ttl_minutes IS NOT NULL AND ttl_minutes BETWEEN 1 AND 1440)"
            " OR (type = 'unblock_ip' AND ttl_minutes IS NULL)",
            name="ttl_matches_type",
        ),
        Index("ix_commands_tenant_agent_state", "tenant_id", "agent_id", "state"),
    )
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    ttl_minutes: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(16), server_default="pending", nullable=False)
    created_at: Mapped[datetime] = now_col()
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[str | None] = mapped_column(String(200))


class NotificationChannel(Base):
    __tablename__ = "notification_channels"
    __table_args__ = (
        UniqueConstraint("tenant_id", "type", "address", name="uq_notification_channels_tenant_type_address"),
        CheckConstraint("type IN ('email', 'telegram')", name="type_valid"),
    )
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk_col()
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    address: Mapped[str] = mapped_column(String(320), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = now_col()


class AllowlistEntry(Base):
    __tablename__ = "allowlist"
    __table_args__ = (UniqueConstraint("tenant_id", "cidr", name="uq_allowlist_tenant_cidr"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk_col()
    cidr: Mapped[str] = mapped_column(CIDR, nullable=False)
    note: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = now_col()


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_log_tenant_created", "tenant_id", "created_at"),)
    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_fk_col()
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str | None] = mapped_column(String(200))
    created_at: Mapped[datetime] = now_col()
