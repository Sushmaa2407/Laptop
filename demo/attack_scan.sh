#!/usr/bin/env bash
# Run on the ATTACKER VM:   bash attack_scan.sh 192.168.56.103
# A classic port scan: probes ports 1-1000 on the target.
TARGET="${1:?usage: bash attack_scan.sh TARGET_IP}"
echo "Scanning ports 1-1000 on $TARGET ..."
sudo nmap -sS -T4 -p 1-1000 "$TARGET"
