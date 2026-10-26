"""Apply server commands on this machine: block or unblock an IP address with iptables.

Safety rules (the server is trusted, but a bug or a wrong click must not lock the machine out):
- never block loopback, unspecified or multicast addresses, this machine's own addresses, or the Shield server
- blocks are time-limited (ttl) and are removed when they expire or when the agent stops
- a block drops traffic from the address (INPUT) and to the address (OUTPUT)
- the address is validated with the ipaddress module and passed as a list argument (no shell)
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
import time

log = logging.getLogger("shield.response")


class Responder:
    def __init__(self, protected: set[str] | None = None, dry_run: bool = False) -> None:
        self._protected = {self._norm(a) for a in (protected or set()) if self._norm(a)}
        self._dry_run = dry_run
        self._blocked: dict[str, float] = {}  # ip -> unix time when the block ends

    @staticmethod
    def _norm(value: str) -> str | None:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    # ------------------------------------------------------------ public
    def apply(self, command: dict) -> tuple[str, str]:
        """Run one command. Returns (state, message) where state is 'applied' or 'failed'."""
        ip = self._norm(str(command.get("ip", "")))
        if ip is None:
            return "failed", "invalid ip"
        kind = command.get("type")
        if kind == "block_ip":
            return self._block(ip, int(command.get("ttl_minutes") or 60))
        if kind == "unblock_ip":
            return self._unblock(ip)
        return "failed", f"unknown command type {kind!r}"

    def expire_due(self, now: float | None = None) -> list[str]:
        """Remove blocks whose time is up. Returns the addresses that were unblocked."""
        now = now if now is not None else time.time()
        done = []
        for ip, until in list(self._blocked.items()):
            if now >= until:
                self._run(ip, add=False)
                self._blocked.pop(ip, None)
                done.append(ip)
        return done

    def shutdown(self) -> None:
        for ip in list(self._blocked):
            self._run(ip, add=False)
            self._blocked.pop(ip, None)

    # ------------------------------------------------------------ internals
    def _refuse_reason(self, ip: str) -> str | None:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            return "refused: loopback/unspecified/multicast address"
        if ip in self._protected:
            return "refused: this machine or the Shield server"
        return None

    def _block(self, ip: str, ttl_minutes: int) -> tuple[str, str]:
        reason = self._refuse_reason(ip)
        if reason:
            return "failed", reason
        if not self._run(ip, add=True):
            return "failed", "iptables failed (is the agent running as root?)"
        self._blocked[ip] = time.time() + ttl_minutes * 60
        return "applied", f"blocked for {ttl_minutes} min"

    def _unblock(self, ip: str) -> tuple[str, str]:
        self._run(ip, add=False)
        self._blocked.pop(ip, None)
        return "applied", "unblocked"

    def _run(self, ip: str, *, add: bool) -> bool:
        """Add or remove the block in both directions: nothing from the address in, nothing to it out."""
        tool = "ip6tables" if ":" in ip else "iptables"
        if self._dry_run:
            log.info("[dry-run] %s %s %s", tool, "block" if add else "unblock", ip)
            return True
        if shutil.which(tool) is None:
            log.error("%s not found", tool)
            return False
        ok = True
        for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
            rule = [chain, flag, ip, "-j", "DROP"]
            exists = subprocess.run([tool, "-w", "5", "-C", *rule], capture_output=True, check=False).returncode == 0
            if add and exists or not add and not exists:
                continue
            cmd = [tool, "-w", "5", "-I", chain, "1", flag, ip, "-j", "DROP"] if add else [tool, "-w", "5", "-D", *rule]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                log.error("%s failed: %s", " ".join(cmd), result.stderr.strip())
                ok = False
        return ok
