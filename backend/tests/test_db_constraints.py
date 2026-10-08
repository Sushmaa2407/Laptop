"""The database itself refuses cross-tenant links and invalid values (second wall behind the code)."""
import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.db.models import Agent, AgentCommand, Alert, Flow, Tenant, User

pytestmark = pytest.mark.skipif(
    "TEST_DATABASE_URL" not in os.environ, reason="needs TEST_DATABASE_URL (run: source scripts/dev-env.sh)"
)


@pytest.fixture
async def session():
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as s:
        yield s
        await s.rollback()  # nothing in these tests is ever committed


async def two_tenants(session):
    t1, t2 = Tenant(name="one"), Tenant(name="two")
    session.add_all([t1, t2])
    await session.flush()
    a1 = Agent(tenant_id=t1.id, name="a1", api_key_hash="a" * 64)
    a2 = Agent(tenant_id=t2.id, name="a2", api_key_hash="b" * 64)
    session.add_all([a1, a2])
    await session.flush()
    return t1, t2, a1, a2


def make_flow(tenant_id, agent_id, flow_id):
    return Flow(
        tenant_id=tenant_id, flow_id=flow_id, agent_id=agent_id, start_ts=datetime.now(timezone.utc),
        src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=1, dst_port=2, protocol="tcp", duration_s=1.0,
        fwd_packets=1, bwd_packets=1, fwd_bytes=1, bwd_bytes=1, pkt_len_mean=1.0, pkt_len_std=0.0,
        iat_mean_s=0.0, syn_count=0, rst_count=0, fin_count=0, uniq_dst_ports_60s=1, uniq_dst_ips_60s=1,
    )


async def must_fail(session, obj):
    with pytest.raises(IntegrityError):
        async with session.begin_nested():
            session.add(obj)
            await session.flush()


async def test_alert_cannot_point_at_another_tenants_agent(session):
    t1, t2, a1, _ = await two_tenants(session)
    await must_fail(session, Alert(tenant_id=t2.id, agent_id=a1.id, severity="low", evidence={}))


async def test_flow_cannot_point_at_another_tenants_agent(session):
    t1, t2, a1, _ = await two_tenants(session)
    await must_fail(session, make_flow(t2.id, a1.id, uuid.uuid4()))


async def test_two_tenants_may_use_the_same_flow_id(session):
    t1, t2, a1, a2 = await two_tenants(session)
    same = uuid.uuid4()
    session.add_all([make_flow(t1.id, a1.id, same), make_flow(t2.id, a2.id, same)])
    await session.flush()  # must not raise: the primary key includes tenant_id


async def test_command_rules(session):
    t1, t2, a1, _ = await two_tenants(session)
    await must_fail(session, AgentCommand(tenant_id=t2.id, agent_id=a1.id, type="block_ip", ip="8.8.8.8", ttl_minutes=5))
    await must_fail(session, AgentCommand(tenant_id=t1.id, agent_id=a1.id, type="unblock_ip", ip="8.8.8.8", ttl_minutes=5))
    await must_fail(session, AgentCommand(tenant_id=t1.id, agent_id=a1.id, type="block_ip", ip="8.8.8.8"))


async def test_value_rules(session):
    t1, _, a1, _ = await two_tenants(session)
    await must_fail(session, Alert(tenant_id=t1.id, agent_id=a1.id, severity="catastrophic", evidence={}))
    await must_fail(session, User(tenant_id=t1.id, email="Mixed@Case.com", password_hash="x"))
