# Progress log
## 2026-10-01
- Phase 0: WSL2 memory cap set, Docker works, repo cloned.
- S3 (LLM speed): phi3:mini about 15 tok/s, 12.6 s for 180 tokens. Pass for now; quality comparison in Phase 6.
- S1 (ONNX export): PASS. sklearn 1.9.1, skl2onnx 1.20.0, onnxruntime 1.30.0. ONNX outputs: label, scores. scores == decision_function (higher = more normal, anomalies negative).
- S3 (LLM): phi3:mini 87% GPU / 13% CPU at 4096 context, so it spills. Testing llama3.2:3b next.
- S3 (LLM): PASS. llama3.2:3b 100% GPU, 46 tok/s. Chosen over phi3:mini (ADR-003).
- S4 (Compose + HTTPS baseline): PASS. Postgres, Redis, FastAPI and Caddy local-CA TLS healthy. /readyz returns 503 when Redis is stopped. Whole stack about 150 MiB RAM.
- S2 (capture): PASS for normal traffic. Scapy captured 100% at 1000 pkt/s; losses above about 4-5k pkt/s (noisy). Plan: BPF filter to exclude agent-to-server traffic, report drops in heartbeats, demo attacks at or below 1-2k pkt/s.
- B3 (VM to server over HTTPS with CA check): PASS.
- S2b (raw socket capture): about 97-98% captured at about 1000-1500 pkt/s, kernel drop counter works, 15-21% CPU. Decision: raw AF_PACKET sensor (ADR-005).
- Phase 1.1: shield_common (schemas + IP checks), 59 tests passing.
- Phase 1.2: SQLAlchemy models, Alembic initial migration applied, db_smoke.py proves tenant-link and constraint rules.
- Phase 1.3a: security primitives (Argon2id passwords, HS256 access tokens, opaque refresh tokens, settings) with unit tests.
- Phase 1.3b: register, login, refresh (rotation + reuse detection), logout and /me API with integration tests on shield_test.
- Phase 1.3c: backend image with shield_common + alembic, migrate one-shot service, restart policies, security headers; register/me/refresh verified over HTTPS through Caddy.
- Phase 1.3d: Redis rate limiting for register, login and refresh, with tests; X-Forwarded-For spoofing checked through Caddy.
- Phase 1.4: agent enrollment, agent API keys, heartbeat, tenant-isolation suite and guardrail tests; enrollment flow verified through HTTPS.
