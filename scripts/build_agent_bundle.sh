#!/usr/bin/env bash
# Builds the files users download:   bash scripts/build_agent_bundle.sh [CA_CERT_FILE]
# Output goes to dist/downloads/ (the server serves that folder at /api/v1/downloads/).
# The sensor needs no extra Python packages: only the agent code and one pure-Python file of shared code.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=dist/downloads
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$OUT" "$STAGE/src/shield_common"
cp -r agent/src/shield_agent "$STAGE/src/"
find "$STAGE" -name __pycache__ -type d -prune -exec rm -rf {} +
cp shared/shield_common/src/shield_common/features.py "$STAGE/src/shield_common/"
: > "$STAGE/src/shield_common/__init__.py"
sed -n 's/^AGENT_VERSION = "\(.*\)"/\1/p' agent/src/shield_agent/config.py > "$STAGE/VERSION"

tar czf "$OUT/agent-linux.tgz" -C "$STAGE" src VERSION
(cd "$OUT" && sha256sum agent-linux.tgz > agent-linux.tgz.sha256)
cp agent/install/install.sh agent/install/uninstall.sh "$OUT/"
if [ -n "${1:-}" ]; then cp "$1" "$OUT/ca.crt"; fi

echo "Built $(cat "$STAGE/VERSION") into $OUT:"
ls -l "$OUT"
