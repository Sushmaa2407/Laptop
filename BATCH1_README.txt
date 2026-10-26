BATCH 1 - sensor -> ingestion -> scoring -> alerts -> block
1. Unzip at the repo root (keeps folder paths). It REPLACES backend/app/main.py.
2. backend/requirements.in: add two lines:  numpy  and  onnxruntime
   then recompile requirements.txt with the same command as in that file's header.
3. deploy/docker-compose.yml: paste deploy/docker-compose.worker.snippet.yml under "services:".
4. Train the model:  python ml/scripts/train_model.py --synthetic
5. docker compose -f deploy/docker-compose.yml build && docker compose -f deploy/docker-compose.yml up -d
6. Smoke test:  python scripts/smoke_telemetry.py --server https://localhost --api-key <agent key> [--ca-cert <caddy root.crt>]
