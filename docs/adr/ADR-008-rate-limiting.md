# ADR-008: Rate limiting
- Fixed-window counters in Redis (atomic Lua script). Keys hold SHA-256 digests only.
- Limits: login 30/15min per IP; failed logins 5/15min per (IP, email) and 30/hour per email; register 5/hour per IP; refresh 120/15min per IP.
- Locked-out callers are refused before the password is checked.
- Redis outage: fail closed (503) for these endpoints.
- Client IP comes from uvicorn proxy headers; this is safe only because the API port is not published and Caddy overwrites X-Forwarded-For (verified end to end).
Known trade-off: an attacker can lock a victim out of one IP+email pair for 15 minutes by failing 5 times from that IP; the per-email limit is deliberately higher.
