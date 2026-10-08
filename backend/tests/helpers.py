import uuid

from sqlalchemy import text

API = "/api/v1"
PASSWORD = "correct horse battery"
HEARTBEAT = dict(
    schema_version=1, agent_version="0.1.1", platform="linux", uptime_s=100,
    packets_seen=5000, packets_dropped=0, flows_buffer_dropped=0,
)


async def run_sql(sql: str, **params):
    from app.db.session import get_sessionmaker

    async with get_sessionmaker()() as s:
        result = await s.execute(text(sql), params)
        await s.commit()
        return result


async def purge_domain(domain: str):
    await run_sql(f"DELETE FROM tenants WHERE id IN (SELECT tenant_id FROM users WHERE email LIKE '%@{domain}')")


async def register_tenant(client, domain: str, tenant_name: str = "Acme") -> dict:
    email = f"user-{uuid.uuid4().hex[:8]}@{domain}"
    r = await client.post(
        f"{API}/auth/register", json={"email": email, "password": PASSWORD, "tenant_name": tenant_name}
    )
    assert r.status_code == 201, r.text
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    me = (await client.get(f"{API}/me", headers=headers)).json()
    return {"email": email, "headers": headers, "tenant_id": me["tenant_id"], "user_id": me["user_id"]}


async def enroll_agent(client, tenant: dict, name="laptop-1", platform="linux", version="0.1.0") -> dict:
    created = await client.post(
        f"{API}/agents/enrollment-codes", headers=tenant["headers"], json={"agent_name": name}
    )
    assert created.status_code == 201, created.text
    code = created.json()["code"]
    r = await client.post(f"{API}/agent/enroll", json={"code": code, "platform": platform, "version": version})
    assert r.status_code == 201, r.text
    body = r.json()
    return {
        "agent_id": body["agent_id"],
        "api_key": body["api_key"],
        "headers": {"Authorization": f"Bearer {body['api_key']}"},
        "code": code,
    }
