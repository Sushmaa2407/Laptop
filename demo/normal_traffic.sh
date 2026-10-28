#!/usr/bin/env bash
# Run INSIDE the VM while the sensor is recording normal traffic:   bash normal_traffic.sh 60
# Makes ordinary web, DNS and package-mirror traffic so the model can learn what "normal" looks like.
N="${1:-60}"
for i in $(seq 1 "$N"); do
  curl -s -o /dev/null https://example.com
  curl -s -o /dev/null https://www.wikipedia.org
  curl -s -o /dev/null http://archive.ubuntu.com/ubuntu/dists/noble/Release
  getent hosts github.com >/dev/null
  ping -c 2 -q 1.1.1.1 >/dev/null 2>&1
  echo "round $i/$N"
  sleep $((RANDOM % 8 + 2))
done
