import itertools
import random
import statistics

import pytest

from shield_common.features import (
    FLOW_FEATURE_NAMES,
    HOST_FEATURE_NAMES,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
    FlowAccumulator,
)
from shield_common.schemas import FlowRecord


def build(packets):
    """packets: list of (timestamp, length, forward, tcp_flags)."""
    acc = FlowAccumulator(packets[0][0])
    for ts, length, forward, flags in packets:
        acc.add(ts, length, forward, flags)
    return acc


def test_a_single_packet():
    f = build([(100.0, 60, True, TCP_SYN)]).features()
    assert f["duration_s"] == 0 and f["iat_mean_s"] == 0 and f["pkt_len_std"] == 0
    assert f["pkt_len_mean"] == 60
    assert (f["fwd_packets"], f["bwd_packets"], f["fwd_bytes"], f["bwd_bytes"]) == (1, 0, 60, 0)
    assert f["syn_count"] == 1


def test_matches_the_standard_library_on_random_flows():
    rng = random.Random(1234)
    for _ in range(200):
        ts = 1_790_000_000.0
        packets = []
        for _ in range(rng.randint(2, 300)):
            ts += rng.random() * 3
            packets.append((ts, rng.randint(20, 1500), rng.random() < 0.5, 0))
        f = build(packets).features()
        lengths = [p[1] for p in packets]
        times = [p[0] for p in packets]
        gaps = [b - a for a, b in itertools.pairwise(times)]
        assert f["pkt_len_mean"] == pytest.approx(statistics.mean(lengths), rel=1e-9)
        assert f["pkt_len_std"] == pytest.approx(statistics.stdev(lengths), rel=1e-9)
        assert f["iat_mean_s"] == pytest.approx(statistics.mean(gaps), rel=1e-6)
        assert f["duration_s"] == pytest.approx(times[-1] - times[0])
        assert f["fwd_packets"] == sum(1 for p in packets if p[2])
        assert f["bwd_packets"] == sum(1 for p in packets if not p[2])
        assert f["fwd_bytes"] == sum(p[1] for p in packets if p[2])
        assert f["bwd_bytes"] == sum(p[1] for p in packets if not p[2])


def test_flags_are_counted_per_packet():
    packets = [
        (1.0, 60, True, TCP_SYN),
        (1.1, 60, False, TCP_SYN | 0x10),  # SYN-ACK still counts as a SYN packet
        (1.2, 60, True, 0x10),
        (1.3, 60, True, TCP_FIN | 0x10),
        (1.4, 60, False, TCP_FIN | 0x10),
        (1.5, 60, False, TCP_RST),
        (1.6, 60, True, TCP_SYN | TCP_FIN | TCP_RST),
    ]
    f = build(packets).features()
    assert (f["syn_count"], f["fin_count"], f["rst_count"]) == (3, 3, 2)


def test_time_cannot_run_backwards():
    acc = FlowAccumulator(10.0)
    acc.add(10.0, 60, True)
    acc.add(9.0, 60, True)
    assert acc.last_ts == 10.0 and acc.features()["duration_s"] == 0.0


def test_constant_lengths_have_no_spread():
    acc = FlowAccumulator(0.0)
    for i in range(10_000):
        acc.add(i * 0.001, 1500, i % 2 == 0)
    f = acc.features()
    assert f["pkt_len_std"] == 0.0 and f["pkt_len_mean"] == 1500


def test_feature_names_match_the_wire_schema():
    fields = set(FlowRecord.model_fields)
    assert set(FLOW_FEATURE_NAMES) <= fields and set(HOST_FEATURE_NAMES) <= fields
    assert set(FlowAccumulator(0.0).features()) == set(FLOW_FEATURE_NAMES)
