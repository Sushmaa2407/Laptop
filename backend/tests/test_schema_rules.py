"""Guardrails for future development: tenant isolation rules that new code must follow."""
import inspect

from app.db import models  # noqa: F401  (importing registers the tables)
from app.db.base import Base
from app.repositories import agents as agents_repo

# refresh_tokens belong to a user, and a user belongs to exactly one tenant.
NOT_TENANT_SCOPED = {"tenants", "refresh_tokens"}

# These two functions authenticate a SECRET; the secret itself identifies the tenant.
SECRET_LOOKUPS = {"consume_enrollment_code", "get_active_agent_by_key_hash"}


def test_every_table_has_a_non_null_tenant_id():
    for name, table in Base.metadata.tables.items():
        if name in NOT_TENANT_SCOPED:
            continue
        assert "tenant_id" in table.c, f"table {name} has no tenant_id column"
        assert table.c.tenant_id.nullable is False, f"{name}.tenant_id must be NOT NULL"


def test_every_tenant_data_function_takes_a_tenant_id():
    for name, fn in inspect.getmembers(agents_repo, inspect.isfunction):
        if name.startswith("_") or fn.__module__ != agents_repo.__name__ or name in SECRET_LOOKUPS:
            continue
        assert "tenant_id" in inspect.signature(fn).parameters, f"{name} must take tenant_id"
