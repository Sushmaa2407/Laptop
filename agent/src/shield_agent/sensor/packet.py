"""Defensive parser for raw Ethernet frames.

The sensor reads frames straight from the network, so every byte is hostile input. Rules:
- Never trust a length or offset field: check it against the bytes that really exist before reading.
- Never raise on bad input: return a Skip reason and let the caller count it.
- Never allocate based on an attacker-controlled number.
- Do not verify checksums: offloading makes them unreliable at capture time and we only need metadata.
"""

import enum
import ipaddress
from dataclasses import dataclass

Frame = bytes | bytearray | memoryview

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8})
MAX_VLAN_TAGS = 2

IPV4_MIN_HEADER_LEN = 20
IPV6_HEADER_LEN = 40
MAX_IPV6_EXT_HEADERS = 8

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10

_IPV6_HOP_BY_HOP = 0
_IPV6_ROUTING = 43
_IPV6_FRAGMENT = 44
_IPV6_AUTH_HEADER = 51
_IPV6_DEST_OPTIONS = 60
_IPV6_SIMPLE_EXTENSIONS = frozenset({_IPV6_HOP_BY_HOP, _IPV6_ROUTING, _IPV6_DEST_OPTIONS})


class Skip(enum.Enum):
    """Why a frame was not turned into a ParsedPacket."""

    NOT_IP = "not_ip"  # e.g. ARP: perfectly normal, just not our business
    TRUNCATED = "truncated"  # a header claims more bytes than the frame has
    MALFORMED = "malformed"  # a field has a value no valid packet can have


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    """The few facts the flow assembler needs.

    src/dst are packed addresses (4 or 16 bytes): cheap to hash; use format_address() for text.
    length is the size of the IP packet (headers included), not the Ethernet frame.
    Ports are 0 for protocols without ports and for non-first fragments.
    """

    ip_version: int
    src: bytes
    dst: bytes
    protocol: int
    src_port: int
    dst_port: int
    length: int
    tcp_flags: int
    fragment: bool


def format_address(packed: bytes) -> str:
    return str(ipaddress.ip_address(packed))


def _u16(data: Frame, index: int) -> int:
    return (data[index] << 8) | data[index + 1]


def parse_frame(frame: Frame) -> ParsedPacket | Skip:
    n = len(frame)
    if n < ETH_HEADER_LEN:
        return Skip.TRUNCATED
    ethertype = _u16(frame, 12)
    offset = ETH_HEADER_LEN
    tags = 0
    while ethertype in VLAN_ETHERTYPES:
        if tags >= MAX_VLAN_TAGS:
            return Skip.MALFORMED
        if n < offset + 4:
            return Skip.TRUNCATED
        ethertype = _u16(frame, offset + 2)
        offset += 4
        tags += 1
    if ethertype == ETHERTYPE_IPV4:
        return _parse_ipv4(frame, offset)
    if ethertype == ETHERTYPE_IPV6:
        return _parse_ipv6(frame, offset)
    return Skip.NOT_IP


def _parse_ipv4(frame: Frame, start: int) -> ParsedPacket | Skip:
    n = len(frame)
    if n < start + IPV4_MIN_HEADER_LEN:
        return Skip.TRUNCATED
    first = frame[start]
    if first >> 4 != 4:
        return Skip.MALFORMED
    header_len = (first & 0x0F) * 4
    if header_len < IPV4_MIN_HEADER_LEN:
        return Skip.MALFORMED
    if n < start + header_len:
        return Skip.TRUNCATED

    available = n - start
    total_len = _u16(frame, start + 2)
    if total_len == 0 or total_len > available:
        # Segmentation offload leaves 0 (or a value larger than the frame): use what is really there.
        total_len = available
    elif total_len < header_len:
        return Skip.MALFORMED

    frag_field = _u16(frame, start + 6)
    fragment_offset = frag_field & 0x1FFF
    is_fragment = fragment_offset != 0 or bool(frag_field & 0x2000)
    protocol = frame[start + 9]
    src = bytes(frame[start + 12 : start + 16])
    dst = bytes(frame[start + 16 : start + 20])

    if fragment_offset != 0:  # a later fragment carries no transport header
        return ParsedPacket(4, src, dst, protocol, 0, 0, total_len, 0, True)

    transport = _parse_transport(frame, start + header_len, start + total_len, protocol)
    if isinstance(transport, Skip):
        return transport
    src_port, dst_port, flags = transport
    return ParsedPacket(4, src, dst, protocol, src_port, dst_port, total_len, flags, is_fragment)


def _parse_ipv6(frame: Frame, start: int) -> ParsedPacket | Skip:
    n = len(frame)
    if n < start + IPV6_HEADER_LEN:
        return Skip.TRUNCATED
    if frame[start] >> 4 != 6:
        return Skip.MALFORMED

    available = n - start - IPV6_HEADER_LEN
    payload_len = _u16(frame, start + 4)
    if payload_len == 0 or payload_len > available:
        payload_len = available  # offload or jumbogram: use what is really there
    end = start + IPV6_HEADER_LEN + payload_len
    length = IPV6_HEADER_LEN + payload_len

    next_header = frame[start + 6]
    src = bytes(frame[start + 8 : start + 24])
    dst = bytes(frame[start + 24 : start + 40])
    offset = start + IPV6_HEADER_LEN
    is_fragment = False

    for _ in range(MAX_IPV6_EXT_HEADERS + 1):
        if next_header in _IPV6_SIMPLE_EXTENSIONS:
            if end - offset < 8:
                return Skip.TRUNCATED
            ext_len = (frame[offset + 1] + 1) * 8
            if end - offset < ext_len:
                return Skip.TRUNCATED
            next_header = frame[offset]
            offset += ext_len
        elif next_header == _IPV6_FRAGMENT:
            if end - offset < 8:
                return Skip.TRUNCATED
            fragment_offset = _u16(frame, offset + 2) >> 3
            is_fragment = True
            next_header = frame[offset]
            offset += 8
            if fragment_offset != 0:  # a later fragment carries no transport header
                return ParsedPacket(6, src, dst, next_header, 0, 0, length, 0, True)
        elif next_header == _IPV6_AUTH_HEADER:
            if end - offset < 8:
                return Skip.TRUNCATED
            ext_len = (frame[offset + 1] + 2) * 4
            if end - offset < ext_len:
                return Skip.TRUNCATED
            next_header = frame[offset]
            offset += ext_len
        else:
            break
    else:
        return Skip.MALFORMED  # more extension headers than any sane packet has

    transport = _parse_transport(frame, offset, end, next_header)
    if isinstance(transport, Skip):
        return transport
    src_port, dst_port, flags = transport
    return ParsedPacket(6, src, dst, next_header, src_port, dst_port, length, flags, is_fragment)


def _parse_transport(frame: Frame, offset: int, end: int, protocol: int) -> tuple[int, int, int] | Skip:
    """Read ports and TCP flags. `end` is where the IP packet ends (not where the frame ends)."""
    room = end - offset
    if protocol == PROTO_TCP:
        if room < 20:
            return Skip.TRUNCATED
        data_offset = (frame[offset + 12] >> 4) * 4
        if data_offset < 20:
            return Skip.MALFORMED
        if room < data_offset:
            return Skip.TRUNCATED
        return _u16(frame, offset), _u16(frame, offset + 2), frame[offset + 13]
    if protocol == PROTO_UDP:
        if room < 8:
            return Skip.TRUNCATED
        return _u16(frame, offset), _u16(frame, offset + 2), 0
    if protocol in (PROTO_ICMP, PROTO_ICMPV6):
        if room < 4:
            return Skip.TRUNCATED
        return 0, 0, 0
    return 0, 0, 0  # other protocols: no ports to read
