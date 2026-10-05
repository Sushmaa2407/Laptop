"""IP address checks shared by the server and the agent."""
import ipaddress
from collections.abc import Iterable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class TargetRejected(ValueError):
    """Raised when an address must not be used as a block target."""


def parse_ip(value: str) -> IPAddress:
    """Parse a plain IPv4/IPv6 address. Strict: no spaces, no scope ids (fe80::1%eth0)."""
    ip = ipaddress.ip_address(value)  # raises ValueError for anything invalid
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id:
        raise ValueError("scoped IPv6 addresses are not accepted")
    return ip


def normalize_ip(value: str) -> str:
    """Return the canonical text form of an IP address (raises ValueError if invalid)."""
    return str(parse_ip(value))


def _unwrap_mapped(ip: IPAddress) -> IPAddress:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def validate_block_target(
    value: str, protected: Iterable[str] = (), lab_mode: bool = False
) -> IPAddress:
    """Return the address if it is safe to block, otherwise raise TargetRejected.

    protected: IPs or CIDR ranges that must never be blocked (gateway, DNS, the server...).
    lab_mode: allow private (RFC1918) targets, needed because the lab attacker is private.
    """
    try:
        ip = _unwrap_mapped(parse_ip(value))
    except (ValueError, TypeError) as exc:
        raise TargetRejected("not a valid IP address") from exc

    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
        raise TargetRejected("special-purpose address")
    if not lab_mode and not ip.is_global:
        raise TargetRejected("non-global address (private, shared or documentation range)")
    for entry in protected:
        # A bad entry here is a configuration error, so let ValueError escape.
        if ip in ipaddress.ip_network(entry, strict=False):
            raise TargetRejected("protected address")
    return ip
