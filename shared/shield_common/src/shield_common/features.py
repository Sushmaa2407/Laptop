"""Per-flow statistics, computed one packet at a time in constant memory.

This is the single definition of the flow features. The live sensor and the offline training scripts both
use it, so the model is trained on numbers computed exactly the way the sensor will compute them later.

Definitions (the training data must match every one of them):
- forward = the direction of the first packet seen in the flow
- length = size of the IP packet, headers included
- pkt_len_std = sample standard deviation (n - 1) of packet lengths, both directions together; 0 for one packet
- iat_mean_s = mean gap between consecutive packets, both directions together
               = duration / (packets - 1); 0 for one packet
- syn_count, fin_count, rst_count = number of packets that carry that TCP flag
- duration_s = time of the last packet minus time of the first packet
"""

import math

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04

FLOW_FEATURE_NAMES = (
    "duration_s",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "pkt_len_mean",
    "pkt_len_std",
    "iat_mean_s",
    "syn_count",
    "rst_count",
    "fin_count",
)

# Computed per source host (not per flow) by the flow table; window length is fixed at 60 seconds.
HOST_FEATURE_NAMES = ("uniq_dst_ports_60s", "uniq_dst_ips_60s")


class FlowAccumulator:
    """Running statistics of one flow. Memory use does not depend on the number of packets."""

    __slots__ = (
        "first_ts",
        "last_ts",
        "fwd_packets",
        "bwd_packets",
        "fwd_bytes",
        "bwd_bytes",
        "syn_count",
        "rst_count",
        "fin_count",
        "_mean",
        "_m2",
    )

    def __init__(self, ts: float) -> None:
        self.first_ts = ts
        self.last_ts = ts
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.syn_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self._mean = 0.0
        self._m2 = 0.0

    @property
    def packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    def add(self, ts: float, length: int, forward: bool, tcp_flags: int = 0) -> None:
        if ts > self.last_ts:
            self.last_ts = ts  # time never runs backwards inside a flow
        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
        count = self.fwd_packets + self.bwd_packets
        # Welford's method: stable running mean and sum of squared differences.
        delta = length - self._mean
        self._mean += delta / count
        self._m2 += delta * (length - self._mean)
        if tcp_flags & TCP_SYN:
            self.syn_count += 1
        if tcp_flags & TCP_FIN:
            self.fin_count += 1
        if tcp_flags & TCP_RST:
            self.rst_count += 1

    def features(self) -> dict[str, float | int]:
        count = self.packets
        duration = self.last_ts - self.first_ts
        std = math.sqrt(max(self._m2, 0.0) / (count - 1)) if count > 1 else 0.0
        iat_mean = duration / (count - 1) if count > 1 else 0.0
        return {
            "duration_s": duration,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "pkt_len_mean": self._mean,
            "pkt_len_std": std,
            "iat_mean_s": iat_mean,
            "syn_count": self.syn_count,
            "rst_count": self.rst_count,
            "fin_count": self.fin_count,
        }
