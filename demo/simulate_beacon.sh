#!/usr/bin/env bash
# Run INSIDE the protected VM (shield-endpoint):   bash simulate_beacon.sh ATTACKER_IP [SECONDS_BETWEEN] [COUNT]
# Simulates malware on the protected machine that "phones home" at a fixed rhythm (default every 10 s, 20 times).
# The alert appears after about 90 seconds, once the regular rhythm is visible.
TARGET="${1:?usage: bash simulate_beacon.sh ATTACKER_IP [SECONDS_BETWEEN] [COUNT]}"
GAP="${2:-10}"
COUNT="${3:-20}"
echo "Checking in with $TARGET:8080 every $GAP s, $COUNT times ..."
for i in $(seq 1 "$COUNT"); do
  curl -s -m 3 -o /dev/null "http://$TARGET:8080/checkin?id=$i"
  printf '.'
  sleep "$GAP"
done
echo
