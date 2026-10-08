# ADR-009: Agents, enrollment and tenant isolation
- Enrollment: user creates a one-time code (15 min, hashed in the database); the agent exchanges it for an API key (shk_..., shown once, stored as SHA-256). Claiming a code and creating the agent happen in one transaction.
- Credentials are separate: user JWTs cannot act as agents and agent keys cannot act as users.
- Tenant-owned data is reached only through repository functions that take tenant_id. The two secret lookups are the only exceptions (enforced by tests/test_schema_rules.py).
- Another tenant's resource and a missing resource both return the same 404.
- Guardrail tests: every route needs authentication unless listed as public; every table needs a NOT NULL tenant_id; every tenant-data repository function needs a tenant_id parameter.
- When a new repository module is added (alerts, flows, commands) it must be added to the guardrail test list.
