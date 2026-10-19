import ipaddress
import socket
import struct

import pytest
from frames import (
    ETH_IPV4,
    UDP_HEADER,
    arp,
    frag4_first,
    frag4_next,
    frag6_first,
    frag6_next,
    icmp4,
    ipv6_ext_chain,
    raw_ipv6,
    tcp4,
    tcp6,
    udp4,
    udp6_hop_by_hop,
    vlan_tcp4,
)

from shield_agent.sensor.packet import (
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    ParsedPacket,
    Skip,
    format_address,
    parse_frame,
)


def v4(text):
    return socket.inet_aton(text)


def v6(text):
    return ipaddress.IPv6Address(text).packed


def mutated(frame, index, value):
    data = bytearray(frame)
    data[index] = value
    return bytes(data)


def set_u16(frame, index, value):
    data = bytearray(frame)
    data[index : index + 2] = struct.pack("!H", value)
    return bytes(data)


# Offsets in a plain Ethernet + IPv4 + TCP frame: IP header at 14, TCP header at 34.
IP_START = 14
IP_TOTAL_LEN = IP_START + 2
TCP_DATA_OFFSET = 34 + 12


# ---------------------------------------------------------------- golden frames
@pytest.mark.parametrize(
    "flags", [0x02, 0x12, 0x10, 0x11, 0x04, 0x18, 0x00], ids=["syn", "synack", "ack", "finack", "rst", "pshack", "none"]
)
def test_ipv4_tcp(flags):
    frame = tcp4(src="10.0.0.1", dst="93.184.216.34", sport=51514, dport=443, flags=flags)
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket)
    assert (p.ip_version, p.protocol) == (4, PROTO_TCP)
    assert p.src == v4("10.0.0.1") and p.dst == v4("93.184.216.34")
    assert (p.src_port, p.dst_port) == (51514, 443)
    assert p.tcp_flags == flags and p.fragment is False
    assert p.length == len(frame) - 14


def test_ipv4_tcp_with_options_and_payload():
    frame = tcp4(payload=b"hello", options=[("MSS", 1460), ("NOP", None), ("WScale", 7)])
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket)
    assert (p.src_port, p.dst_port) == (51514, 443)
    assert p.length == len(frame) - 14 and p.length > 45


def test_ipv4_udp():
    frame = udp4(sport=5353, dport=53, payload=b"x" * 50)
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket)
    assert p.protocol == PROTO_UDP and (p.src_port, p.dst_port) == (5353, 53)
    assert p.tcp_flags == 0 and p.length == 20 + 8 + 50


def test_ipv4_icmp_has_no_ports():
    p = parse_frame(icmp4())
    assert isinstance(p, ParsedPacket)
    assert p.protocol == PROTO_ICMP and (p.src_port, p.dst_port) == (0, 0)


def test_ipv4_options_are_skipped_correctly():
    base = tcp4()
    with_options = bytearray(base)
    with_options[14] = 0x46  # header length 24 bytes
    with_options[34:34] = b"\x01\x01\x01\x01"  # four NOP options
    with_options[16:18] = struct.pack("!H", (len(base) - 14) + 4)
    p = parse_frame(bytes(with_options))
    assert isinstance(p, ParsedPacket)
    assert (p.src_port, p.dst_port) == (51514, 443) and p.tcp_flags == 0x02


def test_vlan_tag_is_skipped():
    frame = vlan_tcp4(vlan=10)
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket)
    assert (p.src_port, p.dst_port) == (40000, 80)
    assert p.length == len(frame) - 18


def test_ethernet_padding_is_not_counted():
    frame = udp4(payload=b"") + bytes(18)  # short frames are padded to 60 bytes on the wire
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket)
    assert p.length == 28 and (p.src_port, p.dst_port) == (5353, 53)


def test_ipv4_fragments():
    first = parse_frame(frag4_first())
    assert isinstance(first, ParsedPacket)
    assert first.fragment is True and (first.src_port, first.dst_port) == (1000, 2000)
    later = parse_frame(frag4_next())
    assert isinstance(later, ParsedPacket)
    assert later.fragment is True and (later.src_port, later.dst_port) == (0, 0)


def test_ipv6_tcp():
    frame = tcp6(src="2001:db8::1", dst="2001:db8::2", sport=40000, dport=22, flags=0x12)
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket)
    assert (p.ip_version, p.protocol) == (6, PROTO_TCP)
    assert p.src == v6("2001:db8::1") and p.dst == v6("2001:db8::2")
    assert (p.src_port, p.dst_port, p.tcp_flags) == (40000, 22, 0x12)
    assert p.length == len(frame) - 14


def test_ipv6_hop_by_hop_then_udp():
    frame = udp6_hop_by_hop()
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket)
    assert p.protocol == PROTO_UDP and (p.src_port, p.dst_port) == (5000, 53)
    assert p.length == len(frame) - 14


def test_ipv6_fragments():
    first = parse_frame(frag6_first())
    assert isinstance(first, ParsedPacket)
    assert first.fragment is True and (first.src_port, first.dst_port) == (1000, 2000)
    later = parse_frame(frag6_next())
    assert isinstance(later, ParsedPacket)
    assert later.fragment is True and later.protocol == PROTO_UDP and (later.src_port, later.dst_port) == (0, 0)


def test_ipv6_authentication_header_is_skipped():
    auth = bytes([17, 1]) + bytes(2) + bytes(8)  # 12 bytes: (1 + 2) * 4
    p = parse_frame(raw_ipv6(51, auth + UDP_HEADER))
    assert isinstance(p, ParsedPacket)
    assert p.protocol == PROTO_UDP and (p.src_port, p.dst_port) == (1234, 53)


@pytest.mark.parametrize("next_header", [50, 59, 47])  # ESP, no-next-header, GRE
def test_ipv6_protocols_without_ports(next_header):
    p = parse_frame(raw_ipv6(next_header, bytes(40)))
    assert isinstance(p, ParsedPacket)
    assert p.protocol == next_header and (p.src_port, p.dst_port) == (0, 0)


def test_up_to_eight_extension_headers_are_accepted():
    p = parse_frame(ipv6_ext_chain(8))
    assert isinstance(p, ParsedPacket) and (p.src_port, p.dst_port) == (1234, 53)


def test_buffers_of_any_kind_give_the_same_answer():
    frame = tcp4()
    assert parse_frame(bytearray(frame)) == parse_frame(frame) == parse_frame(memoryview(frame))


def test_format_address_round_trip():
    assert format_address(v4("192.168.56.103")) == "192.168.56.103"
    assert format_address(v6("2001:db8::1")) == "2001:db8::1"


# ---------------------------------------------------------------- not IP / too short
def test_non_ip_frames_are_skipped():
    assert parse_frame(arp()) is Skip.NOT_IP
    assert parse_frame(bytes(12) + b"\x88\xcc" + bytes(40)) is Skip.NOT_IP  # LLDP


@pytest.mark.parametrize("size", [0, 1, 13])
def test_runt_frames(size):
    assert parse_frame(bytes(size)) is Skip.TRUNCATED


def test_every_prefix_of_a_frame_is_skipped_never_a_crash():
    for frame in (tcp4(), tcp6(), udp4(payload=b""), vlan_tcp4()):
        for cut in range(len(frame)):
            assert isinstance(parse_frame(frame[:cut]), Skip), cut


def test_more_than_two_vlan_tags_are_malformed():
    frame = bytes(12) + b"\x81\x00\x00\x01\x81\x00\x00\x02\x81\x00\x00\x03\x08\x00" + bytes(40)
    assert parse_frame(frame) is Skip.MALFORMED


# ---------------------------------------------------------------- malformed IPv4 / TCP / UDP
def test_ipv4_header_fields():
    base = tcp4()
    assert parse_frame(mutated(base, IP_START, 0x44)) is Skip.MALFORMED  # header length 16
    assert parse_frame(mutated(base, IP_START, 0x55)) is Skip.MALFORMED  # version 5
    assert parse_frame(mutated(base, IP_START, 0x4F)) is Skip.TRUNCATED  # claims 60 header bytes
    assert parse_frame(set_u16(base, IP_TOTAL_LEN, 10)) is Skip.MALFORMED  # shorter than its own header


def test_ipv4_length_quirks_from_offloading_are_tolerated():
    base = tcp4(payload=b"hello")
    for claimed in (0, 0xFFFF):
        p = parse_frame(set_u16(base, IP_TOTAL_LEN, claimed))
        assert isinstance(p, ParsedPacket)
        assert p.length == len(base) - 14 and (p.src_port, p.dst_port) == (51514, 443)


def test_transport_header_must_fit_inside_the_ip_packet():
    base = tcp4()  # a full TCP header follows, but the IP length says only 4 bytes of it belong to the packet
    assert parse_frame(set_u16(base, IP_TOTAL_LEN, 24)) is Skip.TRUNCATED


def test_tcp_data_offset():
    base = tcp4()
    assert parse_frame(mutated(base, TCP_DATA_OFFSET, 0x30)) is Skip.MALFORMED  # 12 bytes: too small
    assert parse_frame(mutated(base, TCP_DATA_OFFSET, 0xF0)) is Skip.TRUNCATED  # claims 60 bytes


def test_short_udp_and_icmp():
    udp = udp4(payload=b"")
    assert parse_frame(set_u16(udp, IP_TOTAL_LEN, 20 + 6)) is Skip.TRUNCATED
    icmp = icmp4()
    assert parse_frame(set_u16(icmp, IP_TOTAL_LEN, 20 + 2)) is Skip.TRUNCATED


# ---------------------------------------------------------------- malformed IPv6
def test_ipv6_version_must_be_six():
    assert parse_frame(mutated(tcp6(), 14, 0x40)) is Skip.MALFORMED


def test_nine_extension_headers_are_too_many():
    assert parse_frame(ipv6_ext_chain(9)) is Skip.MALFORMED


def test_extension_header_longer_than_the_packet():
    frame = raw_ipv6(0, bytes([17, 255]) + bytes(6))  # claims (255 + 1) * 8 bytes
    assert parse_frame(frame) is Skip.TRUNCATED


def test_extension_header_cut_short():
    assert parse_frame(raw_ipv6(0, bytes(4))) is Skip.TRUNCATED
    assert parse_frame(raw_ipv6(44, bytes(4))) is Skip.TRUNCATED
    assert parse_frame(raw_ipv6(51, bytes(4))) is Skip.TRUNCATED


def test_ipv6_payload_length_lies_are_clamped():
    frame = raw_ipv6(17, UDP_HEADER, payload_len=0xFFFF)
    p = parse_frame(frame)
    assert isinstance(p, ParsedPacket) and p.length == 40 + len(UDP_HEADER)


def test_ethernet_constant_is_what_the_tests_assume():
    assert bytes(12) + b"\x08\x00" == ETH_IPV4
