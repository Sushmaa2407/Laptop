"""Public downloads for the sensor: installer script, sensor bundle, checksum, CA certificate.

These are deliberately public (no login): a user runs the installer on a machine that has no account yet.
Nothing here is secret. The secret is the one-time enrollment code the installer is given.
The files are produced by scripts/build_agent_bundle.sh and mounted into the container at SHIELD_DOWNLOAD_DIR.
"""

import os
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse

router = APIRouter(prefix="/downloads", tags=["downloads"])

_HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")
_URL = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d+)?$")


def download_dir() -> Path:
    return Path(os.environ.get("SHIELD_DOWNLOAD_DIR", "/downloads"))


def public_base_url(request: Request) -> str:
    """The address users reach the server at. SHIELD_PUBLIC_URL wins; otherwise it is read from the proxy headers.

    The value is pasted into a shell script, so anything that is not a plain http(s) host[:port] is refused.
    """
    configured = os.environ.get("SHIELD_PUBLIC_URL", "").rstrip("/")
    if configured:
        if not _URL.match(configured):
            raise HTTPException(status_code=500, detail="SHIELD_PUBLIC_URL is not a plain http(s) address")
        return configured
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "")).split(",")[0].strip()
    if scheme not in ("http", "https") or not _HOST.match(host):
        raise HTTPException(status_code=400, detail="Cannot work out the server address")
    return f"{scheme}://{host}"


def _file(name: str) -> Path:
    path = download_dir() / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Not available: run scripts/build_agent_bundle.sh on the server")
    return path


@router.get("/install.sh", response_class=PlainTextResponse)
async def install_script(request: Request):
    text = _file("install.sh").read_text().replace("__SERVER_URL__", public_base_url(request))
    return PlainTextResponse(text, media_type="text/x-shellscript")


@router.get("/uninstall.sh", response_class=PlainTextResponse)
async def uninstall_script():
    return PlainTextResponse(_file("uninstall.sh").read_text(), media_type="text/x-shellscript")


@router.get("/agent-linux.tgz")
async def agent_bundle():
    return FileResponse(_file("agent-linux.tgz"), media_type="application/gzip", filename="agent-linux.tgz")


@router.get("/agent-linux.tgz.sha256", response_class=PlainTextResponse)
async def agent_checksum():
    return PlainTextResponse(_file("agent-linux.tgz.sha256").read_text())


@router.get("/ca.crt")
async def ca_certificate():
    return FileResponse(_file("ca.crt"), media_type="application/x-pem-file", filename="ca.crt")
