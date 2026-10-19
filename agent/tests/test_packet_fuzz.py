"""The parser must survive anything. Hypothesis feeds it random, mutated and nearly-valid frames."""

from frames import ALL_GOLDEN, ETH_IPV4, ETH_IPV6, raw_ipv6
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from shield_agent.sensor.packet import PROTO_TCP, PROTO_UDP, ParsedPacket, Skip, parse_frame

FUZZ = settings(max_examples=2000, deadline=None, suppress_health_check=[HealthCheck.too_slow])

ETHERNET_HEADERS = [
    ETH_IPV4,
    ETH_IPV6,
    bytes(12) + b"\x81\x00\x00\x01\x08\x00",
    bytes(12) + b"\x81\x00\x00\x01\x81\x00\x00\x02\x86\xdd",
]


def check_invariants(frame, result):
    assert isinstance(result, ParsedPacket | Skip)
    if isinstance(result, Skip):
        return
    assert result.ip_version in (4, 6)
    assert len(result.src) == len(result.dst) == (4 if result.ip_version == 4 else 16)
    assert 0 <= result.src_port <= 65535 and 0 <= result.dst_port <= 65535
    assert 0 <= result.tcp_flags <= 255
    assert (20 if result.ip_version == 4 else 40) <= result.length <= len(frame)
    if result.protocol not in (PROTO_TCP, PROTO_UDP):
        assert result.src_port == result.dst_port == 0
    if result.protocol != PROTO_TCP:
        assert result.tcp_flags == 0


@st.composite
def mutated_golden_frames(draw):
    data = bytearray(draw(st.sampled_from(ALL_GOLDEN)))
    for _ in range(draw(st.integers(0, 8))):
        index = draw(st.integers(0, len(data) - 1))
        data[index] = draw(st.integers(0, 255))
    return bytes(data[: draw(st.integers(0, len(data)))])


ip_like_frames = st.builds(
    lambda header, first, rest: header + bytes([first]) + rest,
    st.sampled_from(ETHERNET_HEADERS),
    st.sampled_from([0x45, 0x46, 0x4F, 0x60]),
    st.binary(max_size=200),
)

ipv6_with_chains = st.builds(
    raw_ipv6,
    st.sampled_from([0, 6, 17, 43, 44, 50, 51, 58, 59, 60]),
    st.binary(max_size=200),
    st.one_of(st.none(), st.integers(0, 0xFFFF)),
)


@FUZZ
@given(st.binary(max_size=1600))
def test_random_bytes(frame):
    check_invariants(frame, parse_frame(frame))


@FUZZ
@given(mutated_golden_frames())
def test_corrupted_real_frames(frame):
    check_invariants(frame, parse_frame(frame))


@FUZZ
@given(ip_like_frames)
def test_ip_looking_garbage(frame):
    check_invariants(frame, parse_frame(frame))


@FUZZ
@given(ipv6_with_chains)
def test_ipv6_extension_header_soup(frame):
    check_invariants(frame, parse_frame(frame))
