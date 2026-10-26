BATCH 7 - temporal layer (regular check-ins / beaconing)
Needs batches 1-6 and the Redis fix already applied.
1. Unzip at the repo root.
2. docker compose -f deploy/docker-compose.yml up -d --build
3. bash demo/sync_agent_to_vm.sh   (new two-way block), then restart the sensor in the VM.
4. Read docs/TEMPORAL_LAYER.md and the new row in the attack menu of docs/DEMO_RUNBOOK.md.
