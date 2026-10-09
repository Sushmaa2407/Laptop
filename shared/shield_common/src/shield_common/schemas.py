"""Shared data contracts for Laptop Shield.

Rules:
- Every model forbids unknown fields, so contract drift fails loudly.
- Tenant and agent identity are NEVER in these payloads; the server derives them from the API key.
- Changing a field is a contract change: bump the version constant and update every consumer.
"""

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from shield_common.ipcheck import normalize_ip

SCHEMA_VERSION = 1
EVIDENCE_VERSION = 1
MAX_BATCH_FLOWS = 500
MAX_COUNT = 2**40
MAX_BYTES = 2**50
MAX_FLOW_SECONDS = 86_400
MAX_EPOCH = 4_102_444_800  # 2100-01-01

IPStr = Annotated[str, StringConstraints(max_length=64), AfterValidator(normalize_ip)]
Port = Annotated[int, Field(ge=0, le=65535)]
Count = Annotated[int, Field(ge=0, le=MAX_COUNT)]
ByteCount = Annotated[int, Field(ge=0, le=MAX_BYTES)]
FlowSeconds = Annotated[float, Field(ge=0, le=MAX_FLOW_SECONDS, allow_inf_nan=False)]
Epoch = Annotated[float, Field(gt=0, le=MAX_EPOCH, allow_inf_nan=False)]
Measure = Annotated[float, Field(ge=0, le=1e12, allow_inf_nan=False)]
UnitFloat = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{1,64}$")]
VersionStr = Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z.+-]{1,32}$")]

Protocol = Literal["tcp", "udp", "icmp", "other"]
Severity = Literal["low", "medium", "high", "critical"]
Conflict = Literal[
    "rule_hit_but_anomaly_normal",
    "anomalous_but_no_rule",
    "periodic_but_not_anomalous",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- agent -> server
class FlowRecord(_Strict):
    flow_id: UUID  # created by the agent; makes retries idempotent
    src_ip: IPStr
    dst_ip: IPStr
    src_port: Port
    dst_port: Port
    protocol: Protocol
    start_ts: Epoch  # epoch seconds (UTC)
    duration_s: FlowSeconds
    fwd_packets: Count
    bwd_packets: Count
    fwd_bytes: ByteCount
    bwd_bytes: ByteCount
    pkt_len_mean: Measure
    pkt_len_std: Measure
    iat_mean_s: Measure
    syn_count: Count
    rst_count: Count
    fin_count: Count
    uniq_dst_ports_60s: Count  # per source host, sliding window
    uniq_dst_ips_60s: Count


class TelemetryBatch(_Strict):
    schema_version: Literal[1]
    flows: list[FlowRecord] = Field(min_length=1, max_length=MAX_BATCH_FLOWS)


class Heartbeat(_Strict):
    schema_version: Literal[1]
    agent_version: VersionStr
    platform: Literal["linux", "windows", "other"]
    uptime_s: Count
    packets_seen: Count
    packets_dropped: Count  # kernel drops (PACKET_STATISTICS)
    flows_buffer_dropped: Count  # flows discarded from the local offline buffer


# ---------------------------------------------------------------- server -> agent
class Command(_Strict):
    command_id: UUID
    type: Literal["block_ip", "unblock_ip"]
    ip: IPStr
    ttl_minutes: Annotated[int, Field(ge=1, le=1440)] | None = None

    @model_validator(mode="after")
    def _ttl_rules(self):
        if self.type == "block_ip" and self.ttl_minutes is None:
            raise ValueError("block_ip requires ttl_minutes")
        if self.type == "unblock_ip" and self.ttl_minutes is not None:
            raise ValueError("unblock_ip must not set ttl_minutes")
        return self


# ---------------------------------------------------------------- detectors -> UI / LLM
# Numbers, booleans, enums and validated IPs only: never free text from the network.
class FlowSummary(_Strict):
    src_ip: IPStr
    dst_ip: IPStr
    src_port: Port
    dst_port: Port
    protocol: Protocol
    start_ts: Epoch
    duration_s: FlowSeconds


class RuleEvidence(_Strict):
    hit: bool
    list_name: Slug | None = None
    matched: Literal["src_ip", "dst_ip", "heuristic"] | None = None


class AnomalyEvidence(_Strict):
    score: UnitFloat  # 0..1, higher = more anomalous (calibrated from the ONNX score, ADR-004)
    threshold: UnitFloat
    is_anomalous: bool
    model_version: Slug


class TemporalEvidence(_Strict):
    events_seen: Count
    periodicity_score: UnitFloat
    baseline_drift: UnitFloat
    is_periodic: bool


class KeyFeature(_Strict):
    name: Slug
    value: Measure


class Evidence(_Strict):
    evidence_version: Literal[1]
    alert_id: UUID
    flow: FlowSummary
    rule: RuleEvidence
    anomaly: AnomalyEvidence
    temporal: TemporalEvidence
    key_features: list[KeyFeature] = Field(max_length=10)
    conflicts: list[Conflict]
    severity: Severity
    severity_policy_version: Annotated[int, Field(ge=1, le=1000)]
