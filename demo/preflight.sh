#!/usr/bin/env bash
# Run in WSL Ubuntu from the repo root, 10 minutes before the demo:   bash demo/preflight.sh
# Prints OK / FAIL for everything the live demo depends on. Fix every FAIL before you start.
cd "$(dirname "$0")/.." || exit 1
C="docker compose -f deploy/docker-compose.yml"
VM_IP="${VM_IP:-192.168.56.103}"
FAILS=0
ok()  { printf '  [ OK ] %s\n' "$1"; }
bad() { printf '  [FAIL] %s\n         fix: %s\n' "$1" "$2"; FAILS=$((FAILS+1)); }

echo "Containers"
RUNNING="$($C ps --services --status running 2>/dev/null)"
for svc in postgres redis backend-api backend-worker backend-explainer caddy; do
  if grep -qx "$svc" <<<"$RUNNING"; then ok "$svc is running"; else bad "$svc is not running" "$C up -d"; fi
done

echo "Server"
if curl -s --cacert ./caddy-root.crt https://localhost/readyz | grep -q '"postgres":"ok"'; then ok "API answers over HTTPS and sees Postgres and Redis"; else bad "API not ready" "$C logs backend-api --tail 30"; fi

echo "Detection model"
[ -f ml/models/shield_iforest.onnx ] && ok "model file present" || bad "ml/models/shield_iforest.onnx missing" "python ml/scripts/train_model.py --synthetic"
if $C logs backend-worker --tail 400 2>/dev/null | grep -q "model .* loaded"; then ok "worker loaded the model"; else bad "worker has not loaded the model" "$C restart backend-worker"; fi

echo "Assistant (Ollama)"
if curl -s localhost:11434/api/ps | grep -q "llama3.2"; then ok "llama3.2 is loaded in memory (fast answers)"; else bad "llama3.2 is not loaded (first answer would take about a minute)" "ollama run llama3.2:3b  (type /bye after it answers)"; fi

echo "Sensor in the VM"
if ping -c1 -W2 "$VM_IP" >/dev/null 2>&1; then ok "VM $VM_IP reachable"; else bad "VM $VM_IP not reachable" "start shield-endpoint in VirtualBox"; fi
ONLINE="$($C exec -T postgres sh -c "psql -U \$POSTGRES_USER -d \$POSTGRES_DB -Atc \"select count(*) from agents where last_seen_at > now() - interval '45 seconds'\"" 2>/dev/null | tr -d '\r')"
if [ "${ONLINE:-0}" -ge 1 ] 2>/dev/null; then ok "sensor is sending heartbeats"; else bad "no sensor heard in the last 45 s" "in the VM: sudo env PYTHONPATH=\$HOME/shield/agent/src:\$HOME/shield/shared/shield_common/src SHIELD_AGENT_CONFIG=\$HOME/vm-config.json \$HOME/venv/bin/python -m shield_agent run"; fi

echo "Dashboard"
CODE="$(curl -s -o /dev/null -w '%{http_code}' localhost:5173)"
[ "$CODE" = "200" ] && ok "dashboard at http://localhost:5173" || bad "dashboard not running" "cd frontend && npm run dev"

echo
if [ "$FAILS" -eq 0 ]; then echo "All checks passed. Sign in to the dashboard and you are ready."; else echo "$FAILS check(s) failed."; exit 1; fi
