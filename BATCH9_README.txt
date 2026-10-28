BATCH 9 - sign-up screen + route-security test fix
1. Unzip at the repo root.
2. python scripts/allow_public_downloads.py
3. cd backend && DATABASE_URL=postgresql://x:x@localhost/x REDIS_URL=redis://localhost JWT_SECRET=$(python3 -c "print('x'*40)") pytest tests/test_route_security.py
