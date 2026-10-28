"""Train the anomaly model and export it to ONNX.

Usage (from the repo root, inside the repo .venv):

    # 1. Fast path for the demo: learn "normal" from realistic synthetic benign traffic
    python ml/scripts/train_model.py --synthetic

    # 2. Better: learn "normal" from flows recorded on your own lab (JSON lines, one FlowRecord per line)
    python ml/scripts/train_model.py --input ml/data/lab_benign.jsonl

Outputs (in ml/models/):
    shield_iforest.onnx   the model (outputs 'label' and 'scores', as in spike S1)
    shield_iforest.json   feature order, calibration constants, threshold, evaluation numbers

The model is trained on NORMAL traffic only (features are put on a log scale first). Attacks are used only to measure how well it detects them.
Feature order = FLOW_FEATURE_NAMES + HOST_FEATURE_NAMES from shield_common.features, so the
live sensor and the model always agree.
"""

from __future__ import annotations

import argparse
import json
import math
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from shield_common.features import FLOW_FEATURE_NAMES, HOST_FEATURE_NAMES
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest

FEATURES = tuple(FLOW_FEATURE_NAMES) + tuple(HOST_FEATURE_NAMES)
MODEL_VERSION = "iforest-v1"
THRESHOLD = 0.5  # on the calibrated 0..1 score


# ---------------------------------------------------------------- synthetic traffic
def _row(**kw: float) -> list[float]:
    return [float(kw.get(name, 0.0)) for name in FEATURES]


def _tcp_flow(rng: np.random.Generator, kind: str) -> list[float]:
    """One normal TCP conversation: web page, API call, ssh-like session."""
    if kind == "web":
        fwd = int(rng.integers(3, 25))
        bwd = int(rng.integers(3, 60))
        mean = rng.uniform(300, 900)
        dur = rng.lognormal(mean=0.0, sigma=1.0)
    elif kind == "api":
        fwd = int(rng.integers(4, 12))
        bwd = int(rng.integers(4, 12))
        mean = rng.uniform(150, 500)
        dur = rng.lognormal(mean=-1.0, sigma=0.7)
    else:  # interactive (ssh)
        fwd = int(rng.integers(20, 200))
        bwd = int(rng.integers(20, 200))
        mean = rng.uniform(90, 250)
        dur = rng.uniform(5, 100)
    packets = fwd + bwd
    fwd_bytes = fwd * mean * rng.uniform(0.3, 0.8)
    bwd_bytes = bwd * mean * rng.uniform(0.8, 1.4)
    return _row(
        duration_s=dur,
        fwd_packets=fwd,
        bwd_packets=bwd,
        fwd_bytes=fwd_bytes,
        bwd_bytes=bwd_bytes,
        pkt_len_mean=mean,
        pkt_len_std=mean * rng.uniform(0.4, 1.1),
        iat_mean_s=dur / max(packets - 1, 1),
        syn_count=rng.choice([1, 2], p=[0.85, 0.15]),
        rst_count=rng.choice([0, 1], p=[0.92, 0.08]),
        fin_count=rng.choice([1, 2], p=[0.3, 0.7]),
        uniq_dst_ports_60s=rng.integers(1, 6),
        uniq_dst_ips_60s=rng.integers(1, 12),
    )


def _dns_flow(rng: np.random.Generator) -> list[float]:
    mean = rng.uniform(60, 130)
    dur = rng.uniform(0.005, 0.2)
    return _row(
        duration_s=dur,
        fwd_packets=1,
        bwd_packets=1,
        fwd_bytes=mean * 0.6,
        bwd_bytes=mean * 1.4,
        pkt_len_mean=mean,
        pkt_len_std=mean * 0.4,
        iat_mean_s=dur,
        uniq_dst_ports_60s=rng.integers(1, 4),
        uniq_dst_ips_60s=rng.integers(1, 4),
    )


def synth_benign(n: int, rng: np.random.Generator) -> np.ndarray:
    rows = []
    for _ in range(n):
        r = rng.random()
        if r < 0.45:
            rows.append(_tcp_flow(rng, "web"))
        elif r < 0.65:
            rows.append(_tcp_flow(rng, "api"))
        elif r < 0.75:
            rows.append(_tcp_flow(rng, "ssh"))
        else:
            rows.append(_dns_flow(rng))
    return np.asarray(rows, dtype=np.float64)


def synth_attacks(n: int, rng: np.random.Generator) -> dict[str, np.ndarray]:
    """Attack shapes used for evaluation and for the live demo (nmap scan, SYN flood, brute force)."""
    scan, flood, brute = [], [], []
    for _ in range(n):
        scan.append(  # nmap -sS: one SYN out, one RST back, hundreds of ports
            _row(
                duration_s=rng.uniform(0.0005, 0.01),
                fwd_packets=1,
                bwd_packets=rng.choice([0, 1]),
                fwd_bytes=44,
                bwd_bytes=rng.choice([0, 40]),
                pkt_len_mean=rng.uniform(40, 46),
                pkt_len_std=rng.uniform(0, 3),
                iat_mean_s=rng.uniform(0, 0.01),
                syn_count=1,
                rst_count=rng.choice([0, 1]),
                uniq_dst_ports_60s=rng.integers(60, 1000),
                uniq_dst_ips_60s=1,
            )
        )
        flood.append(  # SYN flood: many half-open flows to one target
            _row(
                duration_s=rng.uniform(0.0, 0.002),
                fwd_packets=rng.integers(1, 3),
                bwd_packets=0,
                fwd_bytes=rng.uniform(44, 100),
                pkt_len_mean=rng.uniform(40, 60),
                pkt_len_std=0,
                iat_mean_s=rng.uniform(0, 0.001),
                syn_count=rng.integers(1, 3),
                uniq_dst_ports_60s=rng.integers(1, 3),
                uniq_dst_ips_60s=1,
            )
        )
        pk = int(rng.integers(8, 20))  # SSH/FTP password guessing: short repeated logins
        brute.append(
            _row(
                duration_s=rng.uniform(0.3, 2.0),
                fwd_packets=pk,
                bwd_packets=pk,
                fwd_bytes=pk * rng.uniform(70, 110),
                bwd_bytes=pk * rng.uniform(70, 110),
                pkt_len_mean=rng.uniform(70, 110),
                pkt_len_std=rng.uniform(10, 30),
                iat_mean_s=rng.uniform(0.01, 0.1),
                syn_count=1,
                rst_count=rng.choice([0, 1], p=[0.5, 0.5]),
                fin_count=rng.choice([0, 1]),
                uniq_dst_ports_60s=1,
                uniq_dst_ips_60s=1,
            )
        )
    return {
        "port_scan": np.asarray(scan, dtype=np.float64),
        "syn_flood": np.asarray(flood, dtype=np.float64),
        "brute_force": np.asarray(brute, dtype=np.float64),
    }


# ---------------------------------------------------------------- real flows from the lab
def load_jsonl(path: Path) -> np.ndarray:
    rows = []
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            rows.append([float(rec[name]) for name in FEATURES])
    if len(rows) < 200:
        raise SystemExit(f"Only {len(rows)} flows in {path}; record at least a few hundred of normal traffic.")
    return np.asarray(rows, dtype=np.float64)


# ---------------------------------------------------------------- calibration
def calibrate(decision: np.ndarray, percentile: float) -> tuple[float, float]:
    """Return (t, k): score = 1 / (1 + exp(k * (decision - t))).

    sklearn decision_function: higher = more normal, anomalies are negative.
    t = the given percentile of normal training flows, so the calibrated score is 0.5 there
    (about `percentile` % of normal flows are flagged). k makes the normal median score close to 0.02.
    """
    t = float(np.percentile(decision, percentile))
    median = float(np.median(decision))
    gap = max(median - t, 1e-6)
    k = 4.0 / gap
    return t, k


def calibrated(decision: np.ndarray, t: float, k: float) -> np.ndarray:
    z = np.clip(k * (decision - t), -60, 60)
    return 1.0 / (1.0 + np.exp(z))


def main() -> None:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--synthetic", action="store_true", help="train on synthetic benign traffic")
    src.add_argument("--input", type=Path, help="JSONL of normal FlowRecords recorded in the lab")
    ap.add_argument("--n", type=int, default=20000, help="synthetic benign flows")
    ap.add_argument("--out", type=Path, default=Path("ml/models"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--fp-percent",
        type=float,
        default=3.0,
        help="share of normal flows allowed to score as anomalous (alert threshold); lower = fewer false alarms",
    )
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    if args.synthetic:
        benign = synth_benign(args.n, rng)
        source = "synthetic"
    else:
        benign = load_jsonl(args.input)
        source = f"lab:{args.input.name}"

    benign = np.log1p(benign)  # counts, bytes and durations are heavy-tailed; log scale makes outliers stand out
    split = int(len(benign) * 0.8)
    train, holdout = benign[:split], benign[split:]

    model = IsolationForest(n_estimators=200, contamination="auto", random_state=args.seed, n_jobs=-1)
    model.fit(train)
    t, k = calibrate(model.decision_function(train), args.fp_percent)

    # ---- evaluate: false alarms on unseen normal flows, detection on attack shapes
    metrics: dict[str, float] = {}
    hold_scores = calibrated(model.decision_function(holdout), t, k)
    metrics["false_positive_rate"] = float(np.mean(hold_scores >= THRESHOLD))
    for name, attack in synth_attacks(2000, rng).items():
        sc = calibrated(model.decision_function(np.log1p(attack)), t, k)
        metrics[f"detection_rate_{name}"] = float(np.mean(sc >= THRESHOLD))

    # ---- export to ONNX and prove it matches sklearn
    args.out.mkdir(parents=True, exist_ok=True)
    onnx_model = to_onnx(
        model,
        train[:1].astype(np.float32),
        target_opset={"": 17, "ai.onnx.ml": 3},
        options={id(model): {"score_samples": False}},
    )
    onnx_path = args.out / "shield_iforest.onnx"
    onnx_path.write_bytes(onnx_model.SerializeToString())

    import onnxruntime as ort

    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    sample = np.vstack([holdout[:300], *[np.log1p(a) for a in synth_attacks(100, rng).values()]]).astype(np.float32)
    onnx_scores = np.asarray(sess.run(["scores"], {sess.get_inputs()[0].name: sample})[0]).ravel()
    sk_scores = model.decision_function(sample.astype(np.float64))
    max_diff = float(np.max(np.abs(onnx_scores - sk_scores)))
    if max_diff > 1e-3:
        raise SystemExit(f"ONNX output differs from sklearn by {max_diff}; do not use this export.")

    meta = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "trained_on": source,
        "training_flows": int(len(train)),
        "features": list(FEATURES),
        "transform": "log1p",  # apply np.log1p to the feature vector BEFORE the ONNX model
        "calibration": {"t": t, "k": k, "formula": "1/(1+exp(k*(decision-t)))"},
        "threshold": THRESHOLD,
        "fp_percent": args.fp_percent,
        "metrics": metrics,
        "onnx_vs_sklearn_max_abs_diff": max_diff,
    }
    (args.out / "shield_iforest.json").write_text(json.dumps(meta, indent=2))

    print(f"Saved {onnx_path} ({onnx_path.stat().st_size / 1024:.0f} KB), ONNX vs sklearn max diff {max_diff:.2e}")
    for name, value in metrics.items():
        print(f"  {name:28s} {value:6.1%}")
    if not math.isfinite(t):
        raise SystemExit("calibration failed")


if __name__ == "__main__":
    main()
