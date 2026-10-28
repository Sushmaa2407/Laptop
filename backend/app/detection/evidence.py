"""Turn a flow + rule result + anomaly score into the Evidence record shown in the UI and given to the LLM.

Only numbers, enums and validated IPs go in (never free text from the network).
Severity policy v1:
  rule hit and anomalous  -> high      (critical when the numbers are far past the rule threshold)
  rule hit only           -> medium
  anomalous only          -> low       (only raised when the score is very high, see ANOMALY_ONLY_MIN_SCORE)
"""

from __future__ import annotations

import uuid

from shield_common.schemas import (
    AnomalyEvidence,
    Evidence,
    FlowSummary,
    KeyFeature,
    RuleEvidence,
    TemporalEvidence,
)

from app.detection.rules import BEACONING, RuleHit
from app.detection.temporal import TemporalResult

SEVERITY_POLICY_VERSION = 1
ANOMALY_ONLY_MIN_SCORE = 0.9  # with ~3% of normal flows over 0.5, alert on anomaly alone only when it is clear-cut
KEY_FEATURES = (
    "uniq_dst_ports_60s",
    "uniq_dst_ips_60s",
    "syn_count",
    "fin_count",
    "fwd_packets",
    "bwd_packets",
    "pkt_len_mean",
    "duration_s",
)  # 8 names: the Evidence schema allows 10 key features, two slots are kept for measured rates


def decide_severity(hit: RuleHit | None, anomalous: bool) -> str | None:
    """None means: not worth an alert."""
    if hit and anomalous:
        return "critical" if hit.strong else "high"
    if hit:
        return "critical" if hit.strong else "medium"
    if anomalous:
        return "low"
    return None


def build_evidence(
    *,
    alert_id: uuid.UUID,
    flow: dict,
    hit: RuleHit | None,
    score: float,
    threshold: float,
    model_version: str,
    severity: str,
    extras: dict[str, float] | None = None,
    temporal: TemporalResult | None = None,
    drift: float = 0.0,
) -> Evidence:
    anomalous = score >= threshold
    conflicts = []
    if hit and hit.category != BEACONING and not anomalous:  # a quiet beacon is normal-looking by nature
        conflicts.append("rule_hit_but_anomaly_normal")
    if anomalous and not hit:
        conflicts.append("anomalous_but_no_rule")
    return Evidence(
        evidence_version=1,
        alert_id=alert_id,
        flow=FlowSummary(
            src_ip=flow["src_ip"],
            dst_ip=flow["dst_ip"],
            src_port=flow["src_port"],
            dst_port=flow["dst_port"],
            protocol=flow["protocol"],
            start_ts=flow["start_ts"],
            duration_s=flow["duration_s"],
        ),
        rule=RuleEvidence(hit=hit is not None, list_name=hit.category if hit else None,
                          matched="heuristic" if hit else None),
        anomaly=AnomalyEvidence(score=round(score, 4), threshold=threshold, is_anomalous=anomalous,
                                model_version=model_version),
        temporal=TemporalEvidence(events_seen=temporal.events if temporal else 0, periodicity_score=temporal.score if temporal else 0.0,
                                  baseline_drift=min(1.0, max(0.0, drift)), is_periodic=temporal.is_periodic if temporal else False),
        key_features=[KeyFeature(name=n, value=float(flow[n])) for n in KEY_FEATURES]
        + [KeyFeature(name=n, value=float(v)) for n, v in (extras or {}).items()],
        conflicts=conflicts,
        severity=severity,
        severity_policy_version=SEVERITY_POLICY_VERSION,
    )


def offender_ip(evidence: dict) -> str:
    """The address a person should block or trust for this alert: the attacker for scans and floods,
    the remote address being contacted for beaconing (the protected machine itself is the source there)."""
    flow = evidence["flow"]
    return flow["dst_ip"] if evidence["rule"].get("list_name") == BEACONING else flow["src_ip"]
