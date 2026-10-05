# ADR-006: Database schema
Decisions:
- Every table except tenants carries tenant_id. Links to agents, users and alerts use composite foreign keys that include tenant_id, so the database refuses cross-tenant links.
- flows has primary key (tenant_id, flow_id) so tenants cannot collide on flow ids.
- Deviation from plan section 10.3: flows is a plain table for now (no daily partitioning). Old rows are removed by a retention job; revisit partitioning if load tests show a need.
- Alembic migrations (async) are the only way the schema changes.
- Dev access: Postgres is published on 127.0.0.1 only through deploy/docker-compose.dev.yml.
