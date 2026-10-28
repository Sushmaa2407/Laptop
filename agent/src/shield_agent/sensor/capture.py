"""Raw frame capture from a Linux AF_PACKET socket (ADR-005). Needs root or CAP_NET_RAW."""

from __future__ import annotations

import ipaddress
import socket
import struct
import time
from collections.abc import Iterable
from urllib.parse import urlparse

from shield_agent.sensor.packet import PROTO_TCP, ParsedPacket

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_STATISTICS = 6
RCVBUF_BYTES = 8 * 1024 * 1024


class RawCapture:
    def __init__(self, interface: str | None = None, timeout: float = 0.5) -> None:
        self._interface = interface
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self.packets_seen = 0
        self.packets_dropped = 0  # kernel drops (the socket buffer was full)

    def open(self) -> None:
        if not hasattr(socket, "AF_PACKET"):
            raise SystemExit("Packet capture needs Linux (AF_PACKET). Run the sensor inside WSL/VM, not on Windows.")
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError:
            raise SystemExit("Capture needs root (or CAP_NET_RAW). Re-run with sudo.") from None
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
        if self._interface:
            sock.bind((self._interface, 0))
        sock.settimeout(self._timeout)
        self._sock = sock

    def read(self) -> tuple[bytes, float] | None:
        """One frame and its capture time (epoch seconds), or None if nothing arrived within the timeout."""
        assert self._sock is not None
        try:
            frame = self._sock.recv(65535)
        except TimeoutError:
            return None
        self.packets_seen += 1
        return frame, time.time()

    def refresh_drop_counter(self) -> None:
        """Ask the kernel how many packets it dropped. Reading resets the kernel counter, so we accumulate."""
        assert self._sock is not None
        try:
            raw = self._sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            _packets, drops = struct.unpack("II", raw)
        except OSError:
            return
        self.packets_dropped += drops

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


class SelfTrafficFilter:
    """The sensor must not analyse its own conversation with the Shield server (ADR-005)."""

    def __init__(self, server_url: str) -> None:
        parsed = urlparse(server_url)
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._addresses: set[bytes] = set()
        if parsed.hostname:
            try:
                for info in socket.getaddrinfo(parsed.hostname, self._port, type=socket.SOCK_STREAM):
                    self._addresses.add(ipaddress.ip_address(info[4][0]).packed)
            except (socket.gaierror, ValueError):
                pass  # cannot resolve now; the server is probably unreachable anyway

    @property
    def server_addresses(self) -> set[str]:
        return {str(ipaddress.ip_address(a)) for a in self._addresses}

    def is_own(self, packet: ParsedPacket) -> bool:
        if packet.protocol != PROTO_TCP:
            return False
        return (packet.src in self._addresses and packet.src_port == self._port) or (
            packet.dst in self._addresses and packet.dst_port == self._port
        )


def local_addresses() -> set[str]:
    """IP addresses of this machine (used so we never block ourselves). Best effort."""
    import subprocess

    found: set[str] = set()
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, timeout=5, check=False).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] in ("inet", "inet6"):
                found.add(parts[3].split("/")[0])
    except (OSError, subprocess.SubprocessError):
        pass
    return found


def addresses_from(packed: Iterable[bytes]) -> set[str]:
    return {str(ipaddress.ip_address(a)) for a in packed}
