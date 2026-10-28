"""Fast rules that look at one flow plus its per-source counters. No I/O here: pure functions, easy to test."""

from __future__ import annotations

from dataclasses import dataclass

SCAN_PORTS = 20  # one source touched this many different destination ports within 60 s
SWEEP_HOSTS = 20  # ... or this many different destination hosts
FLOOD_HALF_OPEN_PER_10S = 100  # unfinished connection attempts from one source within 10 s
CRITICAL_PORTS = 200
CRITICAL_FLOOD = 500

BRUTE_FORCE_ATTEMPTS_PER_60S = 10  # finished connections from one source to the same login service within 60 s
CRITICAL_BRUTE_FORCE = 50
# Login services worth watching: ssh, ftp, telnet, smtp, pop3, imap, smb, mssql, mysql, rdp, postgres, vnc.
# (Many short connections to port 443 are normal browsing, so web ports are deliberately not on this list.)
AUTH_PORTS = frozenset({21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900})

PORT_SCAN = "port_scan"
HOST_SWEEP = "host_sweep"
SYN_FLOOD = "syn_flood"
BRUTE_FORCE = "brute_force"
BEACONING = "beaconing"  # raised by the temporal layer (detection/temporal.py), not by check_flow


@dataclass(frozen=True)
class RuleHit:
    category: str  # port_scan | host_sweep | syn_flood
    strong: bool  # True when the numbers are far beyond the threshold (-> critical)


def is_half_open(flow: dict) -> bool:
    """A TCP connection attempt that never became a real conversation: SYN seen, at most 2 packets from the
    source, no FIN. (A flood against an open port still gets SYN-ACKs back, so replies do not matter.)"""
    return flow["protocol"] == "tcp" and flow["syn_count"] >= 1 and flow["fwd_packets"] <= 2 and flow["fin_count"] == 0


def is_login_attempt(flow: dict) -> bool:
    """A short, completed TCP conversation with a login service: what one password guess looks like."""
    return (
        flow["protocol"] == "tcp"
        and flow["dst_port"] in AUTH_PORTS
        and flow["fwd_packets"] >= 3
        and flow["bwd_packets"] >= 3
        and flow["duration_s"] <= 15
    )


def check_flow(flow: dict, half_open_last_10s: int, attempts_last_60s: int = 0) -> RuleHit | None:
    ports = flow["uniq_dst_ports_60s"]
    hosts = flow["uniq_dst_ips_60s"]
    if ports >= SCAN_PORTS:
        return RuleHit(PORT_SCAN, ports >= CRITICAL_PORTS)
    if hosts >= SWEEP_HOSTS:
        return RuleHit(HOST_SWEEP, hosts >= CRITICAL_PORTS)
    if is_half_open(flow) and half_open_last_10s >= FLOOD_HALF_OPEN_PER_10S:
        return RuleHit(SYN_FLOOD, half_open_last_10s >= CRITICAL_FLOOD)
    if is_login_attempt(flow) and attempts_last_60s >= BRUTE_FORCE_ATTEMPTS_PER_60S:
        return RuleHit(BRUTE_FORCE, attempts_last_60s >= CRITICAL_BRUTE_FORCE)
    return None
