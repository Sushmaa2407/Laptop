"""Command line:  python -m shield_agent <enroll|run|record> ...   (run/record need sudo for packet capture)"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from shield_agent.client import ApiError, NetworkError, ShieldClient
from shield_agent.config import AGENT_VERSION, AgentConfig, default_config_path
from shield_agent.runtime import run_sensor


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="shield_agent")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("enroll", help="exchange a one-time enrollment code for an API key")
    e.add_argument("--server", required=True, help="e.g. https://shield.lab")
    e.add_argument("--code", required=True)
    e.add_argument("--ca-cert", help="path to the server's CA certificate")
    e.add_argument("--interface", help="capture only on this interface (default: all)")

    r = sub.add_parser("run", help="capture traffic and send flows to the server")
    r.add_argument("--dry-run-block", action="store_true", help="log block commands instead of running iptables")

    rec = sub.add_parser("record", help="capture normal traffic to a JSONL file for model training (no server needed)")
    rec.add_argument("--out", type=Path, default=Path("ml/data/lab_benign.jsonl"))
    rec.add_argument("--seconds", type=float, default=900)
    rec.add_argument("--interface", help="interface name, or 'all' to capture everywhere (default: from config)")

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(name)s %(message)s")

    if args.cmd == "enroll":
        client = ShieldClient(args.server, ca_cert=args.ca_cert)
        try:
            data = client.enroll(args.code, "linux", AGENT_VERSION)
        except (ApiError, NetworkError) as exc:
            print(f"Enrollment failed: {exc}", file=sys.stderr)
            return 1
        cfg = AgentConfig(args.server, data["api_key"], data["agent_id"], args.ca_cert, args.interface)
        path = cfg.save()
        print(f"Enrolled as '{data['agent_name']}'. Config saved to {path}")
        return 0

    if args.cmd == "run":
        run_sensor(AgentConfig.load(), dry_run_block=args.dry_run_block)
        return 0

    if args.cmd == "record":
        try:
            cfg = AgentConfig.load()
        except SystemExit:  # recording needs no enrollment
            cfg = AgentConfig("https://localhost", "", "", None, args.interface)
        if args.interface:
            cfg.interface = None if args.interface == "all" else args.interface
        run_sensor(cfg, record_to=args.out, seconds=args.seconds)
        print(f"Saved flows to {args.out}  (config path would be {default_config_path()})")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
