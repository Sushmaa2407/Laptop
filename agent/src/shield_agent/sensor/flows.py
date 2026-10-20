"""Flow assembly: turn parsed packets into bidirectional flows, with bounded memory.

- A flow is identified by (protocol, endpoint A, endpoint B); both directions belong to the same flow.
  The sender of the first packet we saw is the "forward" side and becomes the source in the record.
- A flow ends when it is idle too long, lasts too long (active timeout), its TCP connection closes
  (both FINs or an RST, plus a short grace period for the final ACK), the table is full (the least
  recently used flow is evicted), or the sensor shuts down.
- Memory is bounded no matter what the network sends: at most max_flows flows, and the per-source
  history used for scan detection has a global entry budget.
"""

import uuid
from collections import OrderedDict
from dataclasses import dataclass

from shield_agent.sensor.packet import (
    PROTO_ICMP,
    PROTO_ICMPV6,
    PROTO_TCP,
    PROTO_UDP,
    ParsedPacket,
    format_address,
)
from shield_common.features import TCP_FIN, TCP_RST, FlowAccumulator

REASON_IDLE = "idle"
REASON_ACTIVE = "active"
REASON_CLOSED = "closed"
REASON_EVICTED = "evicted"
REASON_SHUTDOWN = "shutdown"

HOST_WINDOW_SECONDS = 60.0  # the "_60s" in the per-source feature names

_PROTOCOL_LABELS = {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp", PROTO_ICMPV6: "icmp"}

FlowKey = tuple[int, bytes, int, bytes, int]


@dataclass(frozen=True, slots=True)
class FinishedFlow:
    ip_version: int
    src: bytes  # the initiator
    dst: bytes
    src_port: int
    dst_port: int
    protocol: int
    start_ts: float
    reason: str
    features: dict[str, float | int]
    uniq_dst_ports_60s: int
    uniq_dst_ips_60s: int


@dataclass(slots=True)
class TableStats:
    packets: int = 0
    flows_created: int = 0
    flows_finished: int = 0
    flows_evicted: int = 0


# ---------------------------------------------------------------- per-source history (scan detection)
class _HostWindow:
    __slots__ = ("ports", "ips")

    def __init__(self) -> None:
        self.ports: OrderedDict[int, float] = OrderedDict()
        self.ips: OrderedDict[bytes, float] = OrderedDict()

    def size(self) -> int:
        return len(self.ports) + len(self.ips)


def _trim(window: OrderedDict, cutoff: float, cap: int) -> None:
    """Drop entries that are too old, or beyond the cap (oldest first; the dict is ordered by last use)."""
    while window:
        oldest = next(iter(window))
        if window[oldest] >= cutoff and len(window) <= cap:
            return
        del window[oldest]


def _touch(window: OrderedDict, key: object, ts: float, cutoff: float, cap: int) -> None:
    window[key] = ts
    window.move_to_end(key)
    _trim(window, cutoff, cap)


class HostTracker:
    """For each source address: which destination ports and addresses it touched in the last 60 seconds.

    Memory is bounded twice: per source (per_host_cap entries per kind) and globally (max_entries).
    When the global budget is exceeded the least recently active source is forgotten.
    """

    def __init__(self, *, max_entries: int = 200_000, per_host_cap: int = 1024) -> None:
        self._max_entries = max_entries
        self._per_host_cap = per_host_cap
        self._hosts: OrderedDict[bytes, _HostWindow] = OrderedDict()
        self._total = 0

    @property
    def total_entries(self) -> int:
        return self._total

    def record(self, src: bytes, dst: bytes, dst_port: int, protocol: int, ts: float) -> tuple[int, int]:
        """Note that src started a flow to dst; return (distinct ports, distinct addresses) in the window."""
        window = self._hosts.get(src)
        if window is None:
            window = _HostWindow()
            self._hosts[src] = window
        else:
            self._hosts.move_to_end(src)
        before = window.size()
        cutoff = ts - HOST_WINDOW_SECONDS
        if protocol in (PROTO_TCP, PROTO_UDP):  # ports only mean something for these
            _touch(window.ports, dst_port, ts, cutoff, self._per_host_cap)
        else:
            _trim(window.ports, cutoff, self._per_host_cap)
        _touch(window.ips, dst, ts, cutoff, self._per_host_cap)
        self._total += window.size() - before
        while self._total > self._max_entries and len(self._hosts) > 1:
            _, evicted = self._hosts.popitem(last=False)
            self._total -= evicted.size()
        return len(window.ports), len(window.ips)


# ---------------------------------------------------------------- the flow table
class _Flow:
    __slots__ = (
        "ip_version",
        "src",
        "dst",
        "src_port",
        "dst_port",
        "protocol",
        "acc",
        "uniq_ports",
        "uniq_ips",
        "fin_fwd",
        "fin_bwd",
        "closing_since",
    )

    def __init__(self, packet: ParsedPacket, ts: float, uniq_ports: int, uniq_ips: int) -> None:
        self.ip_version = packet.ip_version
        self.src = packet.src
        self.dst = packet.dst
        self.src_port = packet.src_port
        self.dst_port = packet.dst_port
        self.protocol = packet.protocol
        self.acc = FlowAccumulator(ts)
        self.uniq_ports = uniq_ports
        self.uniq_ips = uniq_ips
        self.fin_fwd = False
        self.fin_bwd = False
        self.closing_since: float | None = None


def _canonical_key(packet: ParsedPacket) -> FlowKey:
    """Same key for both directions of a conversation."""
    if (packet.src, packet.src_port) <= (packet.dst, packet.dst_port):
        return (packet.protocol, packet.src, packet.src_port, packet.dst, packet.dst_port)
    return (packet.protocol, packet.dst, packet.dst_port, packet.src, packet.src_port)


class FlowTable:
    def __init__(
        self,
        *,
        idle_timeout: float = 30.0,
        active_timeout: float = 120.0,
        close_grace: float = 2.0,
        max_flows: int = 20_000,
        sweep_interval: float = 1.0,
        max_host_entries: int = 200_000,
        max_entries_per_host: int = 1024,
    ) -> None:
        self._idle_timeout = idle_timeout
        self._active_timeout = active_timeout
        self._close_grace = close_grace
        self._max_flows = max_flows
        self._sweep_interval = sweep_interval
        self._flows: OrderedDict[FlowKey, _Flow] = OrderedDict()  # least recently used first
        self._hosts = HostTracker(max_entries=max_host_entries, per_host_cap=max_entries_per_host)
        self._clock = 0.0
        self._next_sweep = 0.0
        self.stats = TableStats()

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    @property
    def host_entries(self) -> int:
        return self._hosts.total_entries

    def process(self, packet: ParsedPacket, ts: float) -> list[FinishedFlow]:
        """Add one packet. Returns the flows that finished because of it (usually none)."""
        ts = self._advance(ts)
        self.stats.packets += 1
        finished: list[FinishedFlow] = []
        if ts >= self._next_sweep:
            finished.extend(self.expire(ts))
            self._next_sweep = ts + self._sweep_interval

        key = _canonical_key(packet)
        flow = self._flows.get(key)
        if flow is not None:
            reason = self._expired_reason(flow, ts)
            if reason is not None:  # stale flow with the same addresses: finish it, start a new one
                del self._flows[key]
                finished.append(self._finish(flow, reason))
                flow = None

        if flow is None:
            if len(self._flows) >= self._max_flows:
                _, oldest = self._flows.popitem(last=False)
                self.stats.flows_evicted += 1
                finished.append(self._finish(oldest, REASON_EVICTED))
            ports, ips = self._hosts.record(packet.src, packet.dst, packet.dst_port, packet.protocol, ts)
            flow = _Flow(packet, ts, ports, ips)
            self.stats.flows_created += 1
            self._flows[key] = flow
            forward = True
        else:
            self._flows.move_to_end(key)
            forward = packet.src == flow.src and packet.src_port == flow.src_port

        flags = packet.tcp_flags if packet.protocol == PROTO_TCP else 0
        flow.acc.add(ts, packet.length, forward, flags)
        if flags & (TCP_FIN | TCP_RST):
            self._note_tcp_state(flow, flags, forward, ts)
        return finished

    def expire(self, now: float) -> list[FinishedFlow]:
        """Finish every flow that has timed out. The sensor also calls this on a timer when traffic is quiet."""
        now = self._advance(now)
        finished: list[FinishedFlow] = []
        for key, flow in list(self._flows.items()):
            reason = self._expired_reason(flow, now)
            if reason is not None:
                del self._flows[key]
                finished.append(self._finish(flow, reason))
        return finished

    def flush_all(self) -> list[FinishedFlow]:
        """Finish everything (used when the sensor stops)."""
        finished = [self._finish(flow, REASON_SHUTDOWN) for flow in self._flows.values()]
        self._flows.clear()
        return finished

    # ------------------------------------------------------------ helpers
    def _advance(self, ts: float) -> float:
        if ts > self._clock:
            self._clock = ts
        return self._clock  # time never runs backwards inside the table

    def _expired_reason(self, flow: _Flow, now: float) -> str | None:
        if flow.closing_since is not None and now - flow.closing_since >= self._close_grace:
            return REASON_CLOSED
        if now - flow.acc.last_ts >= self._idle_timeout:
            return REASON_IDLE
        if now - flow.acc.first_ts >= self._active_timeout:
            return REASON_ACTIVE
        return None

    @staticmethod
    def _note_tcp_state(flow: _Flow, flags: int, forward: bool, ts: float) -> None:
        closing = bool(flags & TCP_RST)
        if flags & TCP_FIN:
            if forward:
                flow.fin_fwd = True
            else:
                flow.fin_bwd = True
            closing = closing or (flow.fin_fwd and flow.fin_bwd)
        if closing and flow.closing_since is None:
            flow.closing_since = ts

    def _finish(self, flow: _Flow, reason: str) -> FinishedFlow:
        self.stats.flows_finished += 1
        return FinishedFlow(
            ip_version=flow.ip_version,
            src=flow.src,
            dst=flow.dst,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            start_ts=flow.acc.first_ts,
            reason=reason,
            features=flow.acc.features(),
            uniq_dst_ports_60s=flow.uniq_ports,
            uniq_dst_ips_60s=flow.uniq_ips,
        )


def to_record(flow: FinishedFlow, flow_id: uuid.UUID) -> dict[str, object]:
    """A dict that matches shield_common.schemas.FlowRecord (ready to send as JSON)."""
    record: dict[str, object] = {
        "flow_id": str(flow_id),
        "src_ip": format_address(flow.src),
        "dst_ip": format_address(flow.dst),
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": _PROTOCOL_LABELS.get(flow.protocol, "other"),
        "start_ts": flow.start_ts,
        "uniq_dst_ports_60s": flow.uniq_dst_ports_60s,
        "uniq_dst_ips_60s": flow.uniq_dst_ips_60s,
    }
    record.update(flow.features)
    return record
