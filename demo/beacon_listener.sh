#!/usr/bin/env bash
# Run on the ATTACKER VM before the beaconing demo:   bash beacon_listener.sh
# A tiny web server on port 8080 that plays the attacker's "command and control" server.
echo "Listening on port 8080 (Ctrl+C to stop) ..."
python3 -m http.server 8080 --bind 0.0.0.0
