"""Send fake flows (normal traffic + a port scan + a SYN flood) as an agent, to test the server without a VM.

    python scripts/smoke_telemetry.py --server https://localhost --api-key shk_... [--ca-cert path]
Then look at the alerts in the API (GET /api/v1/alerts) or:  docker compose exec postgres psql -U shield -c "select severity, dedupe_key from alerts"
"""

import argparse
import json
import ssl
import time
import urllib.request
import uuid


def rec(src, dst, dport, sport, **kw):
    base = dict(flow_id=str(uuid.uuid4()), src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol="tcp",
                start_ts=time.time(), duration_s=0.001, fwd_packets=1, bwd_packets=0, fwd_bytes=44, bwd_bytes=0,
                pkt_len_mean=44.0, pkt_len_std=0.0, iat_mean_s=0.0, syn_count=1, rst_count=0, fin_count=0,
                uniq_dst_ports_60s=1, uniq_dst_ips_60s=1)
    base.update(kw)
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--ca-cert")
    a = ap.parse_args()
    ctx = ssl.create_default_context(cafile=a.ca_cert) if a.ca_cert else ssl.create_default_context()
    flows = [rec("10.9.0.5", "10.9.0.9", 443, 50000, fwd_packets=12, bwd_packets=20, fwd_bytes=3000, bwd_bytes=15000,
                 pkt_len_mean=450.0, pkt_len_std=300.0, duration_s=2.0, iat_mean_s=0.07, fin_count=2)]
    flows += [rec("10.9.0.66", "10.9.0.9", p, 40000 + p, uniq_dst_ports_60s=p) for p in range(1, 120)]
    flows += [rec("10.9.0.77", "10.9.0.9", 80, 30000 + i) for i in range(150)]
    for i in range(0, len(flows), 100):
        body = json.dumps({"schema_version": 1, "flows": flows[i:i + 100]}).encode()
        req = urllib.request.Request(a.server.rstrip("/") + "/api/v1/agent/telemetry", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {a.api_key}"})
        with urllib.request.urlopen(req, context=ctx) as resp:
            print(resp.status, resp.read().decode())


if __name__ == "__main__":
    main()
