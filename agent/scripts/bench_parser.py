"""Rough speed check for the parser. Run: python agent/scripts/bench_parser.py"""

import struct
import time

from shield_agent.sensor.packet import ParsedPacket, parse_frame

tcp = struct.pack("!HHIIBBHHH", 51514, 443, 1, 0, 5 << 4, 0x02, 64240, 0, 0)
ip = struct.pack(
    "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes([10, 0, 0, 1]), bytes([93, 184, 216, 34])
)
frame = bytes(12) + b"\x08\x00" + ip + tcp

count = 200_000
start = time.perf_counter()
for _ in range(count):
    result = parse_frame(frame)
elapsed = time.perf_counter() - start
if not isinstance(result, ParsedPacket):
    raise SystemExit("unexpected parser result")
print(f"{count / elapsed:,.0f} packets per second ({elapsed / count * 1e6:.1f} microseconds each)")
