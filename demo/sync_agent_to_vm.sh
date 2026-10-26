#!/usr/bin/env bash
# Run in WSL Ubuntu from the repo root: copies the current agent code to the VM (asks for the VM password).
cd "$(dirname "$0")/.." || exit 1
VM="${VM_USER:-lab}@${VM_IP:-192.168.56.103}"
tar czf - --exclude=__pycache__ agent/src shared/shield_common/src | ssh "$VM" 'mkdir -p ~/shield && tar xzf - -C ~/shield'
echo "Agent code updated on $VM. Restart the sensor there."
