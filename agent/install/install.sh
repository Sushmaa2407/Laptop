#!/usr/bin/env bash
# Laptop Shield sensor installer for Linux.
#
#   curl -fsSL SERVER/api/v1/downloads/install.sh | sudo bash -s -- --code YOUR_CODE
#
# The code comes from the "Devices" page of the dashboard. It works once and expires after a few minutes.
# What this does: downloads the sensor, checks its checksum, enrolls this machine with your account, and
# starts the sensor as a background service (systemd) that restarts on boot.
set -euo pipefail

SERVER_URL="__SERVER_URL__"
CODE=""
CA_FILE=""
FETCH_CA=0
INTERFACE=""
PREFIX="/opt/shield-agent"
CONF_DIR="/etc/shield-agent"
NO_SERVICE=0
DRY_RUN=0

say() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
run() { if [ "$DRY_RUN" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi; }

usage() {
  cat <<USAGE
Usage: install.sh --code CODE [options]
  --code CODE        enrollment code from the dashboard (required)
  --server URL       server address (default: the server this script came from)
  --ca-cert FILE     trust this certificate authority file (for servers with their own CA)
  --fetch-ca         download the server's CA certificate first (lab setups; trusts the server on first use)
  --interface NAME   capture only on this network interface (default: all)
  --prefix DIR       install directory (default: /opt/shield-agent)
  --no-service       do not create a systemd service
  --dry-run          show what would happen without changing anything
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --code) CODE="${2:-}"; shift 2 ;;
    --server) SERVER_URL="${2:-}"; shift 2 ;;
    --ca-cert) CA_FILE="${2:-}"; shift 2 ;;
    --fetch-ca) FETCH_CA=1; shift ;;
    --interface) INTERFACE="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

# ---- check the inputs before touching anything
[[ "$CODE" =~ ^[A-Za-z0-9]{8,64}$ ]] || die "missing or invalid --code (copy it from the Devices page of the dashboard)"
[[ "$SERVER_URL" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || die "invalid server address: $SERVER_URL"
[[ "$PREFIX" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "invalid --prefix"
[ -z "$INTERFACE" ] || [[ "$INTERFACE" =~ ^[A-Za-z0-9._-]{1,15}$ ]] || die "invalid --interface"
[ -z "$CA_FILE" ] || [ -f "$CA_FILE" ] || die "CA file not found: $CA_FILE"
[ "$(uname -s)" = "Linux" ] || die "this installer is for Linux"
[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root (put sudo before bash)"

command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "Python 3.11 or newer is required (found $(python3 -V))"
for tool in curl tar sha256sum; do command -v "$tool" >/dev/null || die "$tool is required"; done
command -v iptables >/dev/null || say "warning: iptables not found: alerts will work but blocking will not"
case "$SERVER_URL" in http://*) say "warning: this server address is not encrypted (http)" ;; esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CURL=(curl -fsSL --retry 3 --connect-timeout 10)

# ---- trust the server's certificate authority (only needed for servers that use their own CA)
if [ "$FETCH_CA" = 1 ]; then
  say "Fetching the server's CA certificate (trusting it on first use)"
  curl -fsSLk --connect-timeout 10 "$SERVER_URL/api/v1/downloads/ca.crt" -o "$TMP/ca.crt" || die "could not download the CA certificate"
  if command -v openssl >/dev/null; then
    say "CA fingerprint: $(openssl x509 -in "$TMP/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
  fi
  run mkdir -p "$CONF_DIR"
  run install -m 0644 "$TMP/ca.crt" "$CONF_DIR/ca.crt"
  CA_FILE="$CONF_DIR/ca.crt"
fi
[ -z "$CA_FILE" ] || CURL+=(--cacert "$CA_FILE")

# ---- download and verify
say "Downloading the sensor from $SERVER_URL"
if [ "$DRY_RUN" = 1 ]; then
  say "[dry-run] would download agent-linux.tgz and its checksum, verify, and unpack into $PREFIX"
else
  "${CURL[@]}" "$SERVER_URL/api/v1/downloads/agent-linux.tgz" -o "$TMP/agent.tgz"
  "${CURL[@]}" "$SERVER_URL/api/v1/downloads/agent-linux.tgz.sha256" -o "$TMP/agent.sha256"
  expected="$(cut -d' ' -f1 "$TMP/agent.sha256")"
  actual="$(sha256sum "$TMP/agent.tgz" | cut -d' ' -f1)"
  [ "$expected" = "$actual" ] || die "checksum mismatch: the download is damaged or was tampered with"
  say "Checksum OK"
  mkdir -p "$PREFIX"
  rm -rf "$PREFIX/src"
  tar xzf "$TMP/agent.tgz" -C "$PREFIX" --no-same-owner
fi

# ---- enroll this machine
say "Enrolling this machine"
ENROLL=(python3 -m shield_agent enroll --server "$SERVER_URL" --code "$CODE")
[ -z "$CA_FILE" ] || ENROLL+=(--ca-cert "$CA_FILE")
[ -z "$INTERFACE" ] || ENROLL+=(--interface "$INTERFACE")
if [ "$DRY_RUN" = 1 ]; then
  say "[dry-run] would run: PYTHONPATH=$PREFIX/src ${ENROLL[*]}"
else
  PYTHONPATH="$PREFIX/src" "${ENROLL[@]}"
fi

# ---- run it as a service
if [ "$NO_SERVICE" = 1 ]; then
  say "Done. Start the sensor with:  sudo env PYTHONPATH=$PREFIX/src python3 -m shield_agent run"
  exit 0
fi
if ! command -v systemctl >/dev/null; then
  say "systemd not found. Start the sensor with:  sudo env PYTHONPATH=$PREFIX/src python3 -m shield_agent run"
  exit 0
fi
say "Creating the service"
UNIT=/etc/systemd/system/shield-agent.service
if [ "$DRY_RUN" = 1 ]; then
  say "[dry-run] would write $UNIT and start it"
else
  cat > "$UNIT" <<UNITFILE
[Unit]
Description=Laptop Shield sensor
After=network-online.target
Wants=network-online.target

[Service]
Environment=PYTHONPATH=$PREFIX/src
ExecStart=$(command -v python3) -m shield_agent run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITFILE
  systemctl daemon-reload
  systemctl enable --now shield-agent
fi
say "Done. The sensor is running. Check it with:  systemctl status shield-agent   (logs: journalctl -u shield-agent -f)"
say "Your machine should appear on the Devices page within about 30 seconds."
