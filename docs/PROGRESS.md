# Progress log
## 2026-10-01
- Phase 0: WSL2 memory cap set, Docker works, repo cloned.
- S3 (LLM speed): phi3:mini about 15 tok/s, 12.6 s for 180 tokens. Pass for now; quality comparison in Phase 6.
- S1 (ONNX export): PASS. sklearn 1.9.1, skl2onnx 1.20.0, onnxruntime 1.30.0. ONNX outputs: label, scores. scores == decision_function (higher = more normal, anomalies negative).
- S3 (LLM): phi3:mini 87% GPU / 13% CPU at 4096 context, so it spills. Testing llama3.2:3b next.
- S3 (LLM): PASS. llama3.2:3b 100% GPU, 46 tok/s. Chosen over phi3:mini (ADR-003).
- S4 (Compose + HTTPS baseline): PASS. Postgres, Redis, FastAPI and Caddy local-CA TLS healthy. /readyz returns 503 when Redis is stopped. Whole stack about 150 MiB RAM.
