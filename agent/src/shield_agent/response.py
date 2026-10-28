"""Apply server commands on this machine: block or unblock an IP address with iptables.

Safety rules (the server is trusted, but a bug or a wrong click must not lock the machine out):
- never block loopback, unspecified or multicast addresses, this machine's own addresses, or the Shield server
- blocks are time-limited (ttl); they are remembered in a small state file, so a restarted agent still removes
  them on time (otherwise a restart would leave firewall rules behind forever)
- a block drops traffic from the address (INPUT) and to the address (OUTPUT)
- the address is validated with the ipaddress module and passed as a list argument (no shell)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

log = logging.getLogger("shield.response")


class Responder:
    def __init__(self, protected: set[str] | None = None, dry_run: bool = False, state_path: Path | None = None) -> None:
        self._protected = {self._norm(a) for a in (protected or set()) if self._norm(a)}
        self._dry_run = dry_run
        self._state_path = state_path
        self._blocked: dict[str, float] = {}  # ip -> unix time when the block ends
        self._load()

    def _load(self) -> None:
        """Pick up blocks from before a restart: keep the ones still running, remove the ones that ended."""
        if self._state_path is None or not self._state_path.exists():
            return
        try:
            saved = json.loads(self._state_path.read_text())
        except (OSError, ValueError):
            return
        now = time.time()
        for ip, until in saved.items():
            if self._norm(ip) is None or not isinstance(until, (int, float)):
                continue
            if until > now:
                self._blocked[ip] = float(until)
            else:
                self._run(ip, add=False)
        self._save()

    def _save(self) -> None:
        if self._state_path is None:
            return
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(self._blocked, fh)
            os.replace(tmp, self._state_path)
        except OSError as exc:
            log.warning("could not save block state: %s", exc)

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
        if done:
            self._save()
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
        self._save()
        return "applied", f"blocked for {ttl_minutes} min"

    def _unblock(self, ip: str) -> tuple[str, str]:
        self._run(ip, add=False)
        self._blocked.pop(ip, None)
        self._save()
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
