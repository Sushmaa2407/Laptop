# Laptop Shield

[![CI](https://github.com/Sushmaa2407/Laptop/actions/workflows/ci.yml/badge.svg)](https://github.com/Sushmaa2407/Laptop/actions/workflows/ci.yml)

Endpoint detection with human-in-the-loop prevention and an evidence-grounded LLM explanation layer.
Final-year B.E. project (solo). Full plan: [docs/MASTER_PLAN.md](docs/MASTER_PLAN.md). Progress log: [docs/PROGRESS.md](docs/PROGRESS.md).

## Status

Phase 0 (feasibility spikes) and Phase 1 (foundation) are complete. Phase 2 (Linux sensor and ingestion pipeline) is next.

## What exists today

- FastAPI backend behind HTTPS (Caddy): registration, login, token refresh, logout, `/me`
- Agent enrollment with one-time codes, agent API keys, heartbeat endpoint
- PostgreSQL schema with tenant isolation enforced in code and by the database
- Redis rate limiting on the authentication endpoints
- Shared contracts package in `shared/shield_common`
- CI on every change: lint, tests against real Postgres and Redis, dependency audit, Docker build, secret scan

## Run the stack

Needs Docker (Docker Desktop with WSL2 on Windows).

    git clone https://github.com/Sushmaa2407/Laptop.git
    cd Laptop/deploy
    cat > .env << EOF
    POSTGRES_DB=shield
    POSTGRES_USER=shield
    POSTGRES_PASSWORD=$(openssl rand -hex 16)
    REDIS_PASSWORD=$(openssl rand -hex 16)
    JWT_SECRET=$(openssl rand -hex 32)
    EOF
    docker compose up -d --build
    docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
    curl --cacert caddy-root.crt https://localhost/readyz

## Develop

1. Create `deploy/.env` as above and add the line `COMPOSE_FILE=docker-compose.yml:docker-compose.dev.yml` (publishes Postgres and Redis on 127.0.0.1 for tests).
2. Create a Python 3.12 virtual environment in `.venv`, then `pip install -r backend/requirements-dev.txt -e shared/shield_common`.
3. Run `source scripts/dev-env.sh` in every new terminal.
4. Once, from `deploy/`: `docker compose exec postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "CREATE DATABASE shield_test"'`, then from `backend/`: `DATABASE_URL="$TEST_DATABASE_URL" alembic upgrade head`.
5. `scripts/check.sh` runs the same checks as CI. Run it before every push.

## Workflow

`main` is protected. Work on a branch, open a pull request, wait for the five CI checks, then squash-merge.
Dependencies are pinned: edit `backend/requirements.in` or `requirements-dev.in`, then re-run `pip-compile --strip-extras`.
