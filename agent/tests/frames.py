"""Frame builders for tests.

Scapy builds the golden frames, so the expected values do not depend on our own parser's
understanding of the formats. Scapy is a test-only dependency.
"""

import struct

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw

ETH_IPV4 = bytes(12) + b"\x08\x00"
ETH_IPV6 = bytes(12) + b"\x86\xdd"
UDP_HEADER = struct.pack("!HHHH", 1234, 53, 8, 0)


def _with_payload(layers, payload):
    return layers / Raw(payload) if payload else layers


def tcp4(src="10.0.0.1", dst="93.184.216.34", sport=51514, dport=443, flags=0x02, payload=b"", options=None):
    layers = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, options=options or [])
    return bytes(_with_payload(layers, payload))


def udp4(src="10.0.0.1", dst="8.8.8.8", sport=5353, dport=53, payload=b"query"):
    layers = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    return bytes(_with_payload(layers, payload))


def icmp4():
    return bytes(Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / ICMP())


def vlan_tcp4(vlan=10):
    layers = (
        Ether() / Dot1Q(vlan=vlan) / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags=0x02)
    )
    return bytes(layers)


def frag4_first():
    layers = (
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8", flags="MF", frag=0) / UDP(sport=1000, dport=2000) / Raw(b"x" * 40)
    )
    return bytes(layers)


def frag4_next():
    return bytes(Ether() / IP(src="10.0.0.1", dst="8.8.8.8", proto=17, frag=185) / Raw(b"x" * 24))


def tcp6(src="2001:db8::1", dst="2001:db8::2", sport=40000, dport=22, flags=0x12, payload=b""):
    layers = Ether() / IPv6(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return bytes(_with_payload(layers, payload))


def udp6_hop_by_hop():
    layers = (
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=0)
        / IPv6ExtHdrHopByHop(nh=17)
        / UDP(sport=5000, dport=53)
        / Raw(b"abc")
    )
    return bytes(layers)


def frag6_first():
    layers = (
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=44)
        / IPv6ExtHdrFragment(nh=17, offset=0, m=1)
        / UDP(sport=1000, dport=2000)
        / Raw(b"y" * 30)
    )
    return bytes(layers)


def frag6_next():
    layers = (
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=44)
        / IPv6ExtHdrFragment(nh=17, offset=100, m=0)
        / Raw(b"z" * 24)
    )
    return bytes(layers)


def arp():
    return bytes(Ether() / ARP())


def raw_ipv6(next_header, payload, payload_len=None):
    """Hand-built IPv6 frame, for cases Scapy will not build for us."""
    length = len(payload) if payload_len is None else payload_len
    header = struct.pack("!IHBB", 0x60000000, length, next_header, 64) + bytes(15) + b"\x01" + bytes(15) + b"\x02"
    return ETH_IPV6 + header + payload


def hop_by_hop(next_header):
    return bytes([next_header, 0]) + bytes(6)  # length field 0 means 8 bytes


def ipv6_ext_chain(count):
    """IPv6 frame with `count` hop-by-hop headers followed by a UDP header."""
    payload = b"".join(hop_by_hop(0) for _ in range(count - 1)) + hop_by_hop(17) + UDP_HEADER
    return raw_ipv6(0, payload)


ALL_GOLDEN = [
    tcp4(),
    tcp4(payload=b"hello", options=[("MSS", 1460), ("NOP", None), ("WScale", 7)]),
    udp4(),
    icmp4(),
    vlan_tcp4(),
    frag4_first(),
    frag4_next(),
    tcp6(),
    udp6_hop_by_hop(),
    frag6_first(),
    frag6_next(),
    ipv6_ext_chain(3),
]
