"""Rough speed check for parser + flow table together. Run: python agent/scripts/bench_flows.py"""

import struct
import time

from shield_agent.sensor.flows import FlowTable
from shield_agent.sensor.packet import parse_frame


def make_frame(sport, dport, src, dst, flags):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 64240, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
    return bytes(12) + b"\x08\x00" + ip + tcp


client = bytes([10, 0, 0, 1])
server = bytes([93, 184, 216, 34])
frames = []
for port in range(2000, 4000):  # 2,000 flows, a packet in each direction
    frames.append(make_frame(port, 443, client, server, 0x10))
    frames.append(make_frame(443, port, server, client, 0x10))

table = FlowTable()
count = 200_000
start = time.perf_counter()
for i in range(count):
    parsed = parse_frame(frames[i % len(frames)])
    table.process(parsed, 1_790_000_000.0 + i * 0.001)
elapsed = time.perf_counter() - start
print(f"{count / elapsed:,.0f} packets per second through parser + flow table")
print(f"active flows at the end: {table.active_flows}")
