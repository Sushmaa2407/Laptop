import json
import uuid

import pytest

from app.detection.evidence import build_evidence
from app.detection.explain import (
    build_messages,
    clamp_action,
    parse_llm_answer,
    template_explanation,
)
from app.detection.rules import RuleHit


def evidence(severity="high", hit=True, score=0.8):
    flow = dict(src_ip="10.0.0.66", dst_ip="10.0.0.9", src_port=40000, dst_port=22, protocol="tcp", start_ts=1.8e9,
                duration_s=0.01, fwd_packets=1, bwd_packets=0, syn_count=1, rst_count=0, fin_count=0,
                pkt_len_mean=44.0, iat_mean_s=0.0, uniq_dst_ports_60s=150, uniq_dst_ips_60s=1)
    ev = build_evidence(alert_id=uuid.uuid4(), flow=flow, hit=RuleHit("port_scan", False) if hit else None,
                        score=score, threshold=0.5, model_version="iforest-v1", severity=severity)
    return ev.model_dump(mode="json")


GOOD = json.dumps({"summary": "A host probed many ports on this machine. That is typical of a scan. We are fairly sure.",
                   "reasons": ["150 ports in 60 seconds", "anomaly score 0.80"], "recommended_action": "block"})


def test_good_answer_is_accepted():
    out = parse_llm_answer(GOOD, "high", evidence())
    assert out["recommended_action"] == "block" and len(out["reasons"]) == 2


@pytest.mark.parametrize("raw", ["not json", "{}", json.dumps({"summary": "short", "reasons": ["x"], "recommended_action": "block"}),
                                 json.dumps({"summary": "x" * 50, "reasons": ["abc"], "recommended_action": "delete_everything"})])
def test_bad_answers_are_rejected(raw):
    with pytest.raises(ValueError):
        parse_llm_answer(raw, "high", evidence())


def test_clamp_action():
    assert clamp_action("allow", "critical") == "monitor"
    assert clamp_action("block", "low") == "monitor"
    assert clamp_action("monitor", "high") == "monitor"


def test_prompt_has_facts_and_no_raw_ports():
    msgs = build_messages(evidence())
    payload = json.loads(msgs[1]["content"])
    assert set(payload) == {"severity", "source_ip", "target_ip", "facts", "conflicts"}
    assert "150 different ports" in payload["facts"][0]
    assert "src_port" not in msgs[1]["content"] and "40000" not in msgs[1]["content"]


def answer(summary, reasons=("150 ports in 60 seconds", "anomaly score 0.80")):
    return json.dumps({"summary": summary, "reasons": list(reasons), "recommended_action": "block"})


@pytest.mark.parametrize("summary", [
    "The destination port 368 is a common port for malicious activity. It looks bad. We are sure.",  # invented number
    "10.0.0.66 scanned 8.8.8.8 and it looks bad. This is typical of a scan. We are fairly sure.",  # invented address
    "A host probed this machine and we are very sure about it.",  # one sentence
])
def test_ungrounded_answers_are_rejected(summary):
    with pytest.raises(ValueError):
        parse_llm_answer(answer(summary), "high", evidence())


def test_grounded_answer_with_ips_and_numbers_is_accepted():
    ok = "10.0.0.66 touched 150 ports on 10.0.0.9. That is typical of a scan. We are fairly sure (score 0.80)."
    assert parse_llm_answer(answer(ok), "high", evidence())["recommended_action"] == "block"


def test_template_covers_each_case():
    t = template_explanation(evidence())
    assert "150 different ports" in t["summary"] and t["recommended_action"] == "block"
    mixed = template_explanation(evidence(severity="medium", score=0.2))
    assert mixed["recommended_action"] == "monitor"
    anomaly_only = template_explanation(evidence(severity="low", hit=False, score=0.95))
    assert "anomaly score alone" in " ".join(anomaly_only["reasons"])


def test_brute_force_facts_and_template():
    flow = dict(src_ip="10.0.0.66", dst_ip="10.0.0.9", src_port=40000, dst_port=22, protocol="tcp", start_ts=1.8e9,
                duration_s=0.6, fwd_packets=14, bwd_packets=16, syn_count=1, rst_count=0, fin_count=2,
                pkt_len_mean=90.0, iat_mean_s=0.04, uniq_dst_ports_60s=1, uniq_dst_ips_60s=1)
    ev = build_evidence(alert_id=uuid.uuid4(), flow=flow, hit=RuleHit("brute_force", False), score=0.3, threshold=0.5,
                        model_version="iforest-v1", severity="medium", extras={"repeat_connections_60s": 31}).model_dump(mode="json")
    assert len(ev["key_features"]) == 9
    assert "31 separate login connections" in template_explanation(ev)["summary"]
    ok = "10.0.0.66 made 31 login connections to 10.0.0.9 in 60 seconds. That is typical of password guessing. The evidence is moderate."
    assert parse_llm_answer(answer(ok, ("31 connections in 60 seconds", "anomaly score 0.30")), "medium", ev)


def test_beaconing_facts_template_and_offender():
    from app.detection.evidence import offender_ip
    from app.detection.temporal import TemporalResult

    flow = dict(src_ip="10.0.0.5", dst_ip="10.0.0.200", src_port=51000, dst_port=8080, protocol="tcp", start_ts=1.8e9,
                duration_s=0.2, fwd_packets=6, bwd_packets=7, syn_count=1, rst_count=0, fin_count=2,
                pkt_len_mean=120.0, iat_mean_s=0.03, uniq_dst_ports_60s=1, uniq_dst_ips_60s=1)
    ev = build_evidence(alert_id=uuid.uuid4(), flow=flow, hit=RuleHit("beaconing", False), score=0.1, threshold=0.5,
                        model_version="iforest-v1", severity="medium", extras={"beacon_period_s": 10.0, "beacon_events": 12},
                        temporal=TemporalResult(12, 10.0, 0.93, True)).model_dump(mode="json")
    assert ev["conflicts"] == [] and ev["temporal"]["is_periodic"] and offender_ip(ev) == "10.0.0.200"
    assert "12 times at regular intervals of about 10 seconds" in template_explanation(ev)["summary"]
    ok = "10.0.0.5 contacted 10.0.0.200 12 times about every 10 seconds. That regular rhythm can mean malware checking in. We are moderately sure."
    assert parse_llm_answer(answer(ok, ("12 contacts, about every 10 seconds", "regularity 0.93 out of 1")), "medium", ev)
