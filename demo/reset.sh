#!/usr/bin/env bash
# Run in WSL Ubuntu from the repo root between demo runs:   bash demo/reset.sh
# Clears alerts, flows, commands, allowlist and the alert de-duplication so the next attack raises a fresh alert.
cd "$(dirname "$0")/.." || exit 1
C="docker compose -f deploy/docker-compose.yml"
$C exec -T postgres sh -c 'psql -U $POSTGRES_USER -d $POSTGRES_DB -c "truncate alerts, flows, commands, allowlist cascade;"'
$C exec -T redis sh -c "redis-cli --scan --pattern 'shield:dedupe:*' | xargs -r redis-cli del >/dev/null; redis-cli --scan --pattern 'shield:half_open:*' | xargs -r redis-cli del >/dev/null; redis-cli --scan --pattern 'shield:attempts:*' | xargs -r redis-cli del >/dev/null; redis-cli --scan --pattern 'shield:beacon:*' | xargs -r redis-cli del >/dev/null"
echo "Server state cleared."
echo
echo "If you blocked the attacker, also lift the block in the VM (check first, then remove):"
echo "  ssh lab@${VM_IP:-192.168.56.103} 'sudo iptables -S INPUT'"
echo "  ssh lab@${VM_IP:-192.168.56.103} 'sudo iptables -D INPUT -s ATTACKER_IP -j DROP'"
echo "Tip: clicking 'Unblock now' in the dashboard before you reset does this for you."
