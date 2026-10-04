# ADR-005: Capture method
Decision: the sensor reads raw frames from a Linux AF_PACKET socket and parses only the header fields it needs (IPv4/IPv6, TCP/UDP/ICMP) with struct. Scapy is used only for tests (crafting golden PCAPs), not in the live capture path.
Why: spike S2/S2b. Scapy used 59-69% of a core and lost packets inconsistently above about 1000 pkt/s; the raw socket used 15-21% and gives a kernel drop counter (PACKET_STATISTICS).
Consequences:
- Heartbeats report packets seen and dropped, so the dashboard can show "capture overloaded".
- Installer raises net.core.rmem_max (sensor does not get CAP_NET_ADMIN).
- Sensor excludes its own traffic to the Shield server in code.
- IPv6 parsing needs unit tests with crafted PCAPs.
- Test VM limits what we can measure (about 1500 pkt/s); demo attacks stay at or below 1000-1500 pkt/s.
