# ADR-010: CI and dependency management
- Dependencies are pinned with pip-tools: requirements.in / requirements-dev.in are edited by hand; requirements.txt / requirements-dev.txt are generated (pip-compile --strip-extras) and committed. The Docker image and CI install the pinned files.
- Lint and format with ruff (rules E, F, W, I, B, UP, S, ASYNC, SIM); formatting is enforced in CI.
- CI jobs: lint, tests (real Postgres 16 and Redis 7 service containers; migrations applied to an empty database; alembic check), pip-audit of production dependencies (also weekly), Docker build with import and non-root checks plus compose validation, gitleaks over the full git history.
- Actions use major-version tags; Dependabot proposes updates weekly. Hardening later: pin actions to commit SHAs.
- scripts/check.sh runs the same checks locally. Run it before every push.
- Rule: never edit requirements.txt by hand; edit the .in file and re-run pip-compile.
