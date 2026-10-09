#!/usr/bin/env bash
# Runs the same checks as CI on your laptop. Usage: scripts/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/dev-env.sh > /dev/null

echo "== lint and format =="
ruff check .
ruff format --check .

echo "== shared package tests =="
python -m pytest shared/shield_common -q

echo "== backend: migrations apply and match the models =="
(cd backend && DATABASE_URL="$TEST_DATABASE_URL" alembic upgrade head && DATABASE_URL="$TEST_DATABASE_URL" alembic check)

echo "== backend tests =="
(cd backend && python -m pytest -q)

echo "ALL CHECKS PASSED"
