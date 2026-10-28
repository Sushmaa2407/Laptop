"""Agent configuration: where the server is, and the secret this agent got when it enrolled.

Stored as JSON, readable only by its owner (it contains the API key). Location:
  $SHIELD_AGENT_CONFIG, else /etc/shield-agent/config.json when running as root,
  else ~/.config/shield-agent/config.json
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

AGENT_VERSION = "0.1.0"


def default_config_path() -> Path:
    override = os.environ.get("SHIELD_AGENT_CONFIG")
    if override:
        return Path(override)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/etc/shield-agent/config.json")
    return Path.home() / ".config" / "shield-agent" / "config.json"


def default_state_path() -> Path:
    """Where the agent remembers its active firewall blocks between restarts."""
    override = os.environ.get("SHIELD_AGENT_STATE")
    if override:
        return Path(override)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/shield-agent/blocks.json")
    return Path.home() / ".local" / "state" / "shield-agent" / "blocks.json"


@dataclass
class AgentConfig:
    server_url: str  # e.g. https://shield.lab
    api_key: str
    agent_id: str
    ca_cert: str | None = None  # path to the server's CA certificate (Caddy local CA)
    interface: str | None = None  # None = capture on all interfaces

    def save(self, path: Path | None = None) -> Path:
        path = path or default_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(asdict(self), fh, indent=2)
        os.chmod(path, 0o600)
        return path

    @classmethod
    def load(cls, path: Path | None = None) -> AgentConfig:
        path = path or default_config_path()
        try:
            data = json.loads(path.read_text())
        except FileNotFoundError:
            raise SystemExit(f"No agent config at {path}. Run 'python -m shield_agent enroll' first.") from None
        return cls(**data)
