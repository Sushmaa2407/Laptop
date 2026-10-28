#!/usr/bin/env bash
# Removes the Laptop Shield sensor from this machine:   sudo bash uninstall.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root (sudo bash uninstall.sh)"; exit 1; }
PREFIX="${1:-/opt/shield-agent}"

systemctl disable --now shield-agent 2>/dev/null || true
rm -f /etc/systemd/system/shield-agent.service
systemctl daemon-reload 2>/dev/null || true

# lift any firewall blocks the sensor still holds
python3 - <<'PY'
import ipaddress, json, subprocess
try:
    blocks = json.load(open("/var/lib/shield-agent/blocks.json"))
except (OSError, ValueError):
    blocks = {}
for ip in blocks:
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        continue
    tool = "ip6tables" if ":" in ip else "iptables"
    for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
        subprocess.run([tool, "-w", "5", "-D", chain, flag, ip, "-j", "DROP"], capture_output=True)
    print("lifted block on", ip)
PY
rm -rf "$PREFIX" /etc/shield-agent /var/lib/shield-agent
echo "Laptop Shield sensor removed. You can also delete the device on the dashboard's Devices page."
