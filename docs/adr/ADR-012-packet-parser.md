# ADR-012: Packet parser
- Pure function parse_frame(frame) -> ParsedPacket | Skip; it never raises on bad input. Skip reasons (not_ip, truncated, malformed) are counted by the sensor and reported in heartbeats.
- Every length and offset is checked against the bytes that exist; transport headers must fit inside the IP packet (Ethernet padding is not trusted).
- IP length 0 or larger than the frame (segmentation offload) is clamped to the available bytes. Checksums are not verified.
- Handles Ethernet, up to 2 VLAN tags, IPv4 (options, fragments), IPv6 (up to 8 extension headers, fragment and authentication headers), TCP, UDP, ICMP. Later fragments have ports 0 (limitation: fragmentation can hide ports).
- Addresses stay packed bytes (cheap to hash); text conversion happens when a flow record is built.
- Tests: golden frames built by Scapy (independent of our own reading of the formats), hand-corrupted frames, and Hypothesis fuzz tests with invariants. Scapy and Hypothesis are test-only.
- Speed: about 290,000 packets per second on the dev laptop (3.4 microseconds per packet), so the parser is not a bottleneck.
- shield-common is deliberately not a declared dependency of shield-agent (dependency confusion on public PyPI); it is installed from its local path.
