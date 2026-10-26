from shield_agent.response import Responder


def test_refuses_dangerous_targets():
    r = Responder(protected={"192.168.1.10"}, dry_run=True)
    cmd = lambda ip: {"type": "block_ip", "ip": ip, "ttl_minutes": 5}  # noqa: E731
    assert r.apply(cmd("127.0.0.1"))[0] == "failed"
    assert r.apply(cmd("192.168.1.10"))[0] == "failed"
    assert r.apply(cmd("not-an-ip"))[0] == "failed"
    assert r.apply(cmd("10.0.0.66"))[0] == "applied"


def test_block_expires():
    r = Responder(dry_run=True)
    r.apply({"type": "block_ip", "ip": "10.0.0.66", "ttl_minutes": 1})
    assert r.expire_due(now=0) == []
    assert r.expire_due(now=10**12) == ["10.0.0.66"]


def test_block_and_unblock_cover_both_directions(monkeypatch):
    import subprocess

    calls = []

    class Done:
        returncode = 1  # "-C" check: rule does not exist yet
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Done()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/sbin/" + name)
    r = Responder()
    r.apply({"type": "block_ip", "ip": "10.0.0.66", "ttl_minutes": 5})
    inserts = [c for c in calls if "-I" in c]
    assert any(c[c.index("-I") + 1] == "INPUT" and "-s" in c for c in inserts)
    assert any(c[c.index("-I") + 1] == "OUTPUT" and "-d" in c for c in inserts)
