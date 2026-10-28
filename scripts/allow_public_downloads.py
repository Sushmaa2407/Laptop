"""Adds the public download routes to the list of public endpoints in backend/tests/test_route_security.py.

    python scripts/allow_public_downloads.py

Safe to run twice. If the file has a layout this script does not recognise it changes nothing and tells you what to add by hand.
"""

import re
import sys
from pathlib import Path

PATH = Path("backend/tests/test_route_security.py")
ROUTES = [
    "/api/v1/downloads/install.sh",
    "/api/v1/downloads/uninstall.sh",
    "/api/v1/downloads/agent-linux.tgz",
    "/api/v1/downloads/agent-linux.tgz.sha256",
    "/api/v1/downloads/ca.crt",
]
MANUAL = "Add these entries to the PUBLIC set by hand:\n" + "\n".join(f'    ("GET", "{r}"),' for r in ROUTES)


def patch(text: str) -> tuple[str, str]:
    """Returns (new_text, message). new_text equals text when nothing was changed."""
    if all(r in text for r in ROUTES):
        return text, "Already patched."
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if re.match(r"^PUBLIC\b[^=]*=\s*(frozenset\()?\{\s*$", line):
            indent = "    "
            for nxt in lines[i + 1 :]:
                if nxt.strip():
                    indent = nxt[: len(nxt) - len(nxt.lstrip())] or indent
                    break
            new = [f'{indent}("GET", "{r}"),' for r in ROUTES if r not in text]
            lines[i + 1 : i + 1] = new
            return "\n".join(lines), f"Added {len(new)} public routes."
    return text, "Could not find a multi-line PUBLIC = {...} block.\n" + MANUAL


def main() -> int:
    if not PATH.exists():
        print(f"{PATH} not found. Run this from the repo root.")
        return 1
    text = PATH.read_text()
    new, message = patch(text)
    if new != text:
        PATH.write_text(new)
    print(message)
    return 0 if ("Added" in message or "Already" in message) else 1


if __name__ == "__main__":
    sys.exit(main())
