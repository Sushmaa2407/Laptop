"""Runs the CIC-IDS2017 evaluation on small generated files that use the same column layout as the real dataset."""

import sys
from pathlib import Path

import numpy as np
import pytest

pd = pytest.importorskip("pandas")
pytest.importorskip("sklearn")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import eval_cicids as ev  # noqa: E402

COLS = ["Flow ID", " Source IP", " Source Port", " Destination IP", " Destination Port", " Protocol", " Timestamp",
        " Flow Duration", " Total Fwd Packets", " Total Backward Packets", "Total Length of Fwd Packets",
        " Total Length of Bwd Packets", " Packet Length Mean", " Packet Length Std", " Flow IAT Mean",
        "FIN Flag Count", " SYN Flag Count", " RST Flag Count", " Label"]


def flows(rng, n, src, dst, dport, minute, label, kind):
    rows = []
    for i in range(n):
        if kind == "web":
            fwd, bwd, dur, mean = int(rng.integers(4, 30)), int(rng.integers(4, 60)), rng.lognormal(12, 1.2), rng.uniform(250, 900)
        elif kind == "scan":
            fwd, bwd, dur, mean = 1, int(rng.integers(0, 2)), rng.uniform(100, 2000), rng.uniform(40, 46)
        else:  # login attempt
            fwd, bwd, dur, mean = int(rng.integers(10, 16)), int(rng.integers(12, 18)), rng.uniform(4e5, 9e5), rng.uniform(80, 110)
        port = int(dport if dport else rng.choice([80, 443, 8080, 53]))
        rows.append([f"{src}-{dst}-{i}", src, int(rng.integers(1024, 65000)), dst, port + (i if kind == "scan" else 0), 6,
                     f"7/7/2017 {minute}", dur, fwd, bwd, fwd * mean * 0.5, bwd * mean, mean, mean * 0.6, dur / max(fwd + bwd - 1, 1),
                     int(kind != "scan"), 1, int(kind == "scan"), label])
    return rows


@pytest.fixture
def data_dir(tmp_path):
    rng = np.random.default_rng(0)
    monday = []
    for h in range(3):
        for m in range(0, 60, 5):
            for s in range(6):
                monday += flows(rng, 12, f"192.168.10.{10 + s}", f"10.1.1.{s + 1}", 0, f"{8 + h}:{m:02d}", "BENIGN", "web")
    friday = []
    for m in range(0, 60, 10):
        for s in range(6):
            friday += flows(rng, 10, f"192.168.10.{10 + s}", f"10.1.1.{s + 1}", 0, f"14:{m:02d}", "BENIGN", "web")
    friday += flows(rng, 600, "172.16.0.1", "192.168.10.50", 0, "14:30", "PortScan", "scan")
    friday += flows(rng, 40, "172.16.0.1", "192.168.10.50", 22, "14:45", "SSH-Patator", "login")
    friday += flows(rng, 60, "172.16.0.1", "192.168.10.50", 80, "14:50", "Web Attack \x96 XSS", "web")
    pd.DataFrame(monday, columns=COLS).to_csv(tmp_path / "Monday-WorkingHours.pcap_ISCX.csv", index=False)
    pd.DataFrame(friday, columns=COLS).to_csv(tmp_path / "Friday-Afternoon.pcap_ISCX.csv", index=False)
    return tmp_path


def test_evaluation_runs_and_finds_the_obvious_attacks(data_dir):
    res = ev.evaluate(data_dir, "Monday", max_train=50_000, per_label=10_000)
    assert res["mode"].startswith("full")
    by = {r["label"]: r for r in res["rows"]}
    assert by["PortScan"]["either"] > 0.9 and by["PortScan"]["rules"] > 0.9
    assert by["SSH-Patator"]["rules"] > 0.8
    assert "Web Attack XSS" in by  # the odd dash character in the label is cleaned
    assert res["fpr_either"] < 0.15


def test_report_is_written_with_the_caveats(data_dir):
    text = ev.render(ev.evaluate(data_dir, "Monday", 50_000, 10_000))
    assert "| PortScan |" in text and "indicative" in text and "tumbling window" in text


def test_flow_only_mode_when_ip_columns_are_missing(data_dir):
    for p in data_dir.glob("*.csv"):
        d = pd.read_csv(p)
        d = d.drop(columns=[c for c in d.columns if c.strip() in ("Source IP", "Destination IP", "Timestamp")])
        d.to_csv(p, index=False)
    res = ev.evaluate(data_dir, "Monday", 50_000, 10_000)
    assert res["mode"].startswith("flow-only") and res["fpr_rules"] == 0.0
