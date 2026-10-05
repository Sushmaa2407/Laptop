import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import Agent, AgentCommand, Alert, Flow, Tenant, User
from app.db.session import get_engine, get_sessionmaker


async def must_fail(session, obj, label):
    try:
        async with session.begin_nested():
            session.add(obj)
            await session.flush()
    except IntegrityError:
        print(f"OK   rejected: {label}")
    else:
        raise SystemExit(f"BAD  accepted: {label}")


async def main():
    Session = get_sessionmaker()
    async with Session() as s:
        t1, t2 = Tenant(name="tenant-one"), Tenant(name="tenant-two")
        s.add_all([t1, t2])
        await s.flush()
        a1 = Agent(tenant_id=t1.id, name="laptop-1", api_key_hash="a" * 64, platform="linux", version="0.1.0")
        s.add(a1)
        await s.flush()

        flow = Flow(
            tenant_id=t1.id, flow_id=uuid.uuid4(), agent_id=a1.id,
            start_ts=datetime.now(timezone.utc), src_ip="192.168.56.103", dst_ip="8.8.8.8",
            src_port=51514, dst_port=443, protocol="tcp", duration_s=1.5,
            fwd_packets=10, bwd_packets=8, fwd_bytes=1200, bwd_bytes=9000,
            pkt_len_mean=566.7, pkt_len_std=400.2, iat_mean_s=0.08,
            syn_count=1, rst_count=0, fin_count=1, uniq_dst_ports_60s=3, uniq_dst_ips_60s=2,
        )
        s.add(flow)
        await s.flush()
        back = (await s.execute(select(Flow.dst_ip))).scalar_one()
        print("OK   flow stored and read back, dst_ip =", back)

        alert = Alert(tenant_id=t1.id, agent_id=a1.id, flow_id=flow.flow_id, severity="high",
                      evidence={"demo": True})
        s.add(alert)
        await s.flush()
        print("OK   alert stored, status =", alert.status)

        s.add(AgentCommand(tenant_id=t1.id, agent_id=a1.id, alert_id=alert.id,
                           type="block_ip", ip="8.8.8.8", ttl_minutes=60))
        await s.flush()
        print("OK   block command stored")

        # --- things that MUST be refused ---
        await must_fail(s, Alert(tenant_id=t2.id, agent_id=a1.id, severity="low", evidence={}),
                        "alert in tenant 2 pointing at tenant 1's agent")
        await must_fail(s, Flow(
            tenant_id=t2.id, flow_id=uuid.uuid4(), agent_id=a1.id,
            start_ts=datetime.now(timezone.utc), src_ip="10.0.0.1", dst_ip="8.8.8.8",
            src_port=1, dst_port=2, protocol="tcp", duration_s=1.0, fwd_packets=1, bwd_packets=1,
            fwd_bytes=1, bwd_bytes=1, pkt_len_mean=1.0, pkt_len_std=0.0, iat_mean_s=0.0,
            syn_count=0, rst_count=0, fin_count=0, uniq_dst_ports_60s=1, uniq_dst_ips_60s=1),
            "flow in tenant 2 pointing at tenant 1's agent")
        await must_fail(s, AgentCommand(tenant_id=t1.id, agent_id=a1.id, type="unblock_ip",
                                        ip="8.8.8.8", ttl_minutes=5),
                        "unblock command with a TTL")
        await must_fail(s, AgentCommand(tenant_id=t1.id, agent_id=a1.id, type="block_ip", ip="8.8.8.8"),
                        "block command without a TTL")
        await must_fail(s, Alert(tenant_id=t1.id, agent_id=a1.id, severity="catastrophic", evidence={}),
                        "alert with an invalid severity")
        await must_fail(s, User(tenant_id=t1.id, email="Mixed@Case.com", password_hash="x"),
                        "user with an upper-case email")

        await s.rollback()
        print("\nAll checks passed. Nothing was saved (rolled back).")
    await get_engine().dispose()


asyncio.run(main())
