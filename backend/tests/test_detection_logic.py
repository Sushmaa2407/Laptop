import uuid

from app.detection.evidence import ANOMALY_ONLY_MIN_SCORE, build_evidence, decide_severity
from app.detection.rules import RuleHit, check_flow


def flow(**kw):
    base = dict(src_ip="10.0.0.66", dst_ip="10.0.0.9", src_port=40000, dst_port=22, protocol="tcp", start_ts=1.8e9,
                duration_s=0.01, fwd_packets=1, bwd_packets=0, syn_count=1, rst_count=0, fin_count=0,
                pkt_len_mean=44.0, iat_mean_s=0.0, uniq_dst_ports_60s=1, uniq_dst_ips_60s=1)
    base.update(kw)
    return base


def test_port_scan_rule():
    assert check_flow(flow(uniq_dst_ports_60s=25), 0).category == "port_scan"
    assert check_flow(flow(uniq_dst_ports_60s=500), 0).strong


def test_syn_flood_needs_many_half_open_flows():
    assert check_flow(flow(), 10) is None
    assert check_flow(flow(), 150).category == "syn_flood"


def test_flood_against_open_port_still_counts():
    # SYN in, SYN-ACK (and retransmits) out, the attacker never completes the handshake
    assert check_flow(flow(bwd_packets=3), 150).category == "syn_flood"


def test_completed_conversation_is_not_half_open():
    assert check_flow(flow(fwd_packets=12, bwd_packets=20, fin_count=2), 500) is None


def test_severity_policy():
    hit = RuleHit("port_scan", strong=False)
    assert decide_severity(hit, True) == "high"
    assert decide_severity(RuleHit("port_scan", True), True) == "critical"
    assert decide_severity(hit, False) == "medium"
    assert decide_severity(None, True) == "low"
    assert decide_severity(None, False) is None


def test_evidence_is_valid_and_flags_conflicts():
    ev = build_evidence(alert_id=uuid.uuid4(), flow=flow(uniq_dst_ports_60s=30), hit=RuleHit("port_scan", False),
                        score=0.2, threshold=0.5, model_version="iforest-v1", severity="medium")
    assert ev.conflicts == ["rule_hit_but_anomaly_normal"]
    ev2 = build_evidence(alert_id=uuid.uuid4(), flow=flow(), hit=None, score=0.95, threshold=0.5,
                         model_version="iforest-v1", severity="low")
    assert ev2.conflicts == ["anomalous_but_no_rule"] and ANOMALY_ONLY_MIN_SCORE <= 0.95


def login_flow(**kw):
    return flow(dst_port=22, fwd_packets=14, bwd_packets=16, fin_count=2, duration_s=0.6, **kw)


def test_brute_force_needs_many_login_connections():
    assert check_flow(login_flow(), 0, 3) is None
    hit = check_flow(login_flow(), 0, 12)
    assert hit.category == "brute_force" and not hit.strong
    assert check_flow(login_flow(), 0, 60).strong


def test_web_browsing_is_not_brute_force():
    # many short connections to a web port are normal
    assert check_flow(login_flow(dst_port=443) if False else flow(dst_port=443, fwd_packets=14, bwd_packets=16, duration_s=0.6), 0, 500) is None
