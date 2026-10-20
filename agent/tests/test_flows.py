import socket
import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from shield_agent.sensor import packet as parser
from shield_agent.sensor.flows import FlowTable, HostTracker, to_record
from shield_agent.sensor.packet import PROTO_ICMP, PROTO_TCP, PROTO_UDP, ParsedPacket
from shield_common import features as shared_features
from shield_common.features import TCP_FIN, TCP_RST, TCP_SYN
from shield_common.schemas import FlowRecord

A = socket.inet_aton("10.0.0.1")
B = socket.inet_aton("93.184.216.34")
ACK = 0x10


def v6(n):
    return bytes([0x20, 0x01, 0x0D, 0xB8]) + bytes(11) + bytes([n])


def pkt(src=A, dst=B, sport=51514, dport=443, proto=PROTO_TCP, flags=0, length=60):
    return ParsedPacket(4, src, dst, proto, sport, dport, length, flags, False)


def reply(p, flags=0, length=60):
    """A packet going the other way in the same conversation."""
    return ParsedPacket(p.ip_version, p.dst, p.src, p.protocol, p.dst_port, p.src_port, length, flags, False)


def packets_in(flows):
    return sum(f.features["fwd_packets"] + f.features["bwd_packets"] for f in flows)


def test_tcp_flag_constants_agree_with_the_parser():
    assert (shared_features.TCP_FIN, shared_features.TCP_SYN, shared_features.TCP_RST) == (
        parser.TCP_FIN,
        parser.TCP_SYN,
        parser.TCP_RST,
    )


# ---------------------------------------------------------------- grouping
def test_both_directions_form_one_flow():
    table = FlowTable()
    syn = pkt(flags=TCP_SYN)
    finished = []
    finished += table.process(syn, 100.0)
    finished += table.process(reply(syn, flags=TCP_SYN | ACK), 100.1)
    finished += table.process(pkt(flags=ACK, length=52), 100.2)
    assert finished == [] and table.active_flows == 1
    (flow,) = table.flush_all()
    assert flow.reason == "shutdown" and flow.start_ts == 100.0
    assert (flow.src, flow.dst, flow.src_port, flow.dst_port) == (A, B, 51514, 443)
    f = flow.features
    assert (f["fwd_packets"], f["bwd_packets"]) == (2, 1)
    assert (f["fwd_bytes"], f["bwd_bytes"]) == (60 + 52, 60)
    assert f["syn_count"] == 2 and f["duration_s"] == pytest.approx(0.2)


def test_the_first_sender_is_the_initiator():
    table = FlowTable()
    table.process(pkt(src=B, dst=A, sport=443, dport=51514), 1.0)
    table.process(pkt(src=A, dst=B, sport=51514, dport=443), 1.1)
    (flow,) = table.flush_all()
    assert (flow.src, flow.src_port) == (B, 443)
    assert (flow.features["fwd_packets"], flow.features["bwd_packets"]) == (1, 1)


# ---------------------------------------------------------------- timeouts
def test_idle_flows_are_emitted_by_the_sweep():
    table = FlowTable(idle_timeout=30.0)
    table.process(pkt(), 100.0)
    assert table.expire(129.9) == []
    (flow,) = table.expire(130.0)
    assert flow.reason == "idle" and table.active_flows == 0


def test_a_packet_after_the_idle_timeout_starts_a_new_flow():
    table = FlowTable(idle_timeout=30.0, sweep_interval=1000.0)  # no sweep: the lookup itself must notice
    table.process(pkt(length=100), 0.0)
    finished = table.process(pkt(length=200), 31.0)
    assert [f.reason for f in finished] == ["idle"] and finished[0].features["fwd_bytes"] == 100
    (new,) = table.flush_all()
    assert new.features["fwd_bytes"] == 200 and new.start_ts == 31.0


def test_active_timeout_splits_long_flows():
    table = FlowTable(idle_timeout=30.0, active_timeout=120.0)
    finished = []
    for i in range(14):  # one packet every 10 seconds: t = 0 ... 130
        finished += table.process(pkt(), i * 10.0)
    assert [f.reason for f in finished] == ["active"]
    assert finished[0].features["fwd_packets"] == 12  # t = 0 ... 110
    (rest,) = table.flush_all()
    assert rest.features["fwd_packets"] == 2  # t = 120 and 130


def test_tcp_close_waits_for_the_final_ack():
    table = FlowTable(close_grace=2.0)
    first = pkt(flags=ACK)
    table.process(first, 0.0)
    table.process(pkt(flags=TCP_FIN | ACK), 1.0)
    table.process(reply(first, flags=TCP_FIN | ACK), 1.1)  # both sides sent FIN: closing starts here
    table.process(pkt(flags=ACK), 1.5)  # the final ACK still joins the same flow
    assert table.expire(3.0) == []  # 1.9 seconds after closing began: still inside the grace period
    (flow,) = table.expire(3.2)
    assert flow.reason == "closed" and flow.features["fin_count"] == 2 and packets_in([flow]) == 4
    table.process(pkt(flags=TCP_SYN), 3.3)  # same addresses and ports again: a new connection
    (again,) = table.flush_all()
    assert again.features["fwd_packets"] == 1


def test_rst_closes_the_flow():
    table = FlowTable(close_grace=2.0)
    first = pkt(flags=TCP_SYN)
    table.process(first, 0.0)
    table.process(reply(first, flags=TCP_RST | ACK), 0.2)
    assert table.expire(1.0) == []
    (flow,) = table.expire(2.3)
    assert flow.reason == "closed" and flow.features["rst_count"] == 1


# ---------------------------------------------------------------- memory limits
def test_full_table_evicts_the_least_recently_used_flow():
    table = FlowTable(max_flows=3)
    for port in (1, 2, 3):
        table.process(pkt(sport=port), 10.0 + port)
    table.process(pkt(sport=1), 14.0)  # flow 1 is now the most recently used
    finished = table.process(pkt(sport=4), 15.0)  # the table is full: flow 2 is the least recently used
    assert [(f.reason, f.src_port) for f in finished] == [("evicted", 2)]
    assert table.active_flows == 3 and table.stats.flows_evicted == 1


def test_a_flood_of_distinct_flows_cannot_exhaust_memory():
    table = FlowTable(max_flows=1000)
    counted = 0
    for i in range(50_000):
        counted += packets_in(table.process(pkt(sport=1 + i), 100.0 + i * 0.0005))
        assert table.active_flows <= 1000
    counted += packets_in(table.flush_all())
    assert counted == 50_000  # every packet landed in some flow, even though most flows were evicted
    assert table.stats.flows_evicted > 0


def test_a_flood_of_spoofed_sources_cannot_exhaust_host_memory():
    table = FlowTable(max_flows=100, max_host_entries=1000, max_entries_per_host=50)
    for i in range(20_000):
        table.process(pkt(src=(0x0A000000 + i).to_bytes(4, "big")), 100.0 + i * 0.0001)
        assert table.host_entries <= 1000


def test_host_tracker_budget_and_window():
    tracker = HostTracker(max_entries=100, per_host_cap=10)
    for i in range(5000):
        tracker.record(i.to_bytes(4, "big"), B, 80, PROTO_TCP, 1000.0 + i * 0.001)
        assert tracker.total_entries <= 100
    for port in range(500):  # one noisy source is capped per host
        ports, ips = tracker.record(A, B, 1000 + port, PROTO_TCP, 2000.0 + port * 0.001)
    assert (ports, ips) == (10, 1)

    tracker = HostTracker()
    for port in range(1, 6):
        tracker.record(A, B, port, PROTO_TCP, 0.0)
    assert tracker.record(A, B, 99, PROTO_TCP, 61.0) == (1, 1)  # everything older than 60 seconds is forgotten


# ---------------------------------------------------------------- scan counters
def test_scan_counters():
    table = FlowTable()
    for i, port in enumerate(range(1000, 1100)):  # a port scan: 100 ports on one host
        table.process(pkt(sport=40_000 + i, dport=port), 10.0 + i * 0.1)
    flows = {f.dst_port: f for f in table.flush_all()}
    assert flows[1000].uniq_dst_ports_60s == 1
    assert flows[1099].uniq_dst_ports_60s == 100 and flows[1099].uniq_dst_ips_60s == 1

    table = FlowTable()
    for i in range(1, 21):  # a host sweep: one port on 20 hosts
        table.process(pkt(dst=bytes([192, 168, 0, i]), dport=22), 10.0 + i * 0.1)
    last = max(table.flush_all(), key=lambda f: f.dst[3])
    assert last.uniq_dst_ips_60s == 20 and last.uniq_dst_ports_60s == 1


def test_scan_counters_forget_after_sixty_seconds():
    table = FlowTable()
    for port in range(1000, 1010):
        table.process(pkt(sport=port, dport=port), 10.0)
    table.process(pkt(sport=5000, dport=5000), 80.0)
    flows = {f.dst_port: f for f in table.flush_all()}
    assert flows[5000].uniq_dst_ports_60s == 1


def test_icmp_does_not_count_ports():
    table = FlowTable()
    for i in range(1, 6):
        table.process(pkt(dst=bytes([10, 1, 1, i]), sport=0, dport=0, proto=PROTO_ICMP), 10.0 + i)
    flows = table.flush_all()
    assert max(f.uniq_dst_ips_60s for f in flows) == 5
    assert all(f.uniq_dst_ports_60s == 0 for f in flows)


def test_time_never_runs_backwards():
    table = FlowTable()
    table.process(pkt(), 10.0)
    table.process(pkt(), 9.0)
    (flow,) = table.flush_all()
    assert flow.features["duration_s"] == 0.0 and flow.start_ts == 10.0


# ---------------------------------------------------------------- the wire contract
@pytest.mark.parametrize(
    ("packet", "label"),
    [
        (pkt(), "tcp"),
        (pkt(proto=PROTO_UDP, dport=53), "udp"),
        (pkt(proto=PROTO_ICMP, sport=0, dport=0), "icmp"),
        (pkt(proto=47, sport=0, dport=0), "other"),
        (ParsedPacket(6, v6(1), v6(2), PROTO_TCP, 40000, 22, 80, TCP_SYN, False), "tcp"),
    ],
)
def test_records_match_the_wire_contract(packet, label):
    table = FlowTable()
    table.process(packet, 1_790_000_000.0)
    table.process(reply(packet), 1_790_000_000.5)
    (flow,) = table.flush_all()
    record = FlowRecord(**to_record(flow, uuid.uuid4()))
    assert record.protocol == label and record.duration_s == pytest.approx(0.5)
    assert (record.fwd_packets, record.bwd_packets) == (1, 1)


# ---------------------------------------------------------------- random streams
HOSTS_V4 = [bytes([10, 0, 0, i]) for i in (1, 2, 3)]
HOSTS_V6 = [v6(i) for i in (1, 2)]


@st.composite
def stream_events(draw):
    version = draw(st.sampled_from([4, 6]))
    hosts = HOSTS_V4 if version == 4 else HOSTS_V6
    protocol = draw(st.sampled_from([PROTO_TCP, PROTO_UDP, PROTO_ICMP, 47]))
    has_ports = protocol in (PROTO_TCP, PROTO_UDP)
    sport = draw(st.sampled_from([1000, 1001, 65535])) if has_ports else 0
    dport = draw(st.sampled_from([53, 80, 443])) if has_ports else 0
    flags = draw(st.integers(0, 255)) if protocol == PROTO_TCP else 0
    packet = ParsedPacket(
        version,
        draw(st.sampled_from(hosts)),
        draw(st.sampled_from(hosts)),
        protocol,
        sport,
        dport,
        draw(st.integers(20, 65535)),
        flags,
        False,
    )
    return draw(st.floats(0, 40)), packet


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(stream_events(), min_size=1, max_size=200), st.integers(1, 20))
def test_random_streams_keep_every_invariant(events, max_flows):
    table = FlowTable(
        max_flows=max_flows,
        idle_timeout=5.0,
        active_timeout=20.0,
        close_grace=1.0,
        max_host_entries=50,
        max_entries_per_host=10,
    )
    now = 1_790_000_000.0
    finished = []
    for dt, packet in events:
        now += dt
        finished += table.process(packet, now)
        assert table.active_flows <= max_flows
        assert table.host_entries <= 50
    finished += table.flush_all()
    assert packets_in(finished) == len(events)  # nothing is ever lost or counted twice
    for flow in finished:
        FlowRecord(**to_record(flow, uuid.uuid4()))  # raises if any flow breaks the wire contract
