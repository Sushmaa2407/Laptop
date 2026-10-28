"""Evaluate the detection approach on the public CIC-IDS2017 dataset (offline, indicative).

What it does
  1. Reads the per-day CSV files of CIC-IDS2017 ("GeneratedLabelledFlows" / "TrafficLabelling" version, which has
     source IP, destination port and timestamp columns).
  2. Maps the dataset's flow measurements onto our 13 features (see FEATURE_MAP and the caveats below).
  3. Trains the same Isolation Forest as the real system (log scale, 200 trees, alert line at the 3rd percentile)
     on Monday, the day that contains only normal traffic.
  4. Tests it on the other days and reports, per attack type, how many flows were flagged by the model, by the
     fixed rules, and by either.

Usage
    pip install pandas scikit-learn numpy
    python ml/scripts/eval_cicids.py --data ml/data/cicids2017 --out docs/EVALUATION_CICIDS2017.md

Honest caveats (also written into the report)
  - CIC-IDS2017 was built with CICFlowMeter, we use our own flow code. Packet-length and flag counting differ in
    detail, flow timeouts differ, so numbers are indicative and not a measurement of the live sensor.
  - The labelled CSVs have timestamps with minute resolution, so the "60 second" host counts here use the minute
    the flow started in (a tumbling window), not our sliding window.
  - Published analyses of CIC-IDS2017 have found labelling and flow-construction errors in it.
  - Only the rules that work on a single flow plus a per-minute count are evaluated (port scan, host sweep, password
    guessing). The SYN-flood and beaconing rules need packet timing the CSVs do not have.
If the CSVs have no source IP or timestamp columns (the "MachineLearningCSV" version), the script runs in flow-only
mode: the two host features are set to 0 and the rules are skipped.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score

# our feature  <-  (dataset column, divisor)
FEATURE_MAP = {
    "duration_s": ("Flow Duration", 1e6),  # microseconds
    "fwd_packets": ("Total Fwd Packets", 1),
    "bwd_packets": ("Total Backward Packets", 1),
    "fwd_bytes": ("Total Length of Fwd Packets", 1),
    "bwd_bytes": ("Total Length of Bwd Packets", 1),
    "pkt_len_mean": ("Packet Length Mean", 1),
    "pkt_len_std": ("Packet Length Std", 1),
    "iat_mean_s": ("Flow IAT Mean", 1e6),
    "syn_count": ("SYN Flag Count", 1),
    "rst_count": ("RST Flag Count", 1),
    "fin_count": ("FIN Flag Count", 1),
}
FLOW_FEATURES = list(FEATURE_MAP)
HOST_FEATURES = ["uniq_dst_ports_60s", "uniq_dst_ips_60s"]

# Mirrors backend/app/detection/rules.py
SCAN_PORTS, SWEEP_HOSTS, BRUTE_PER_MINUTE = 20, 20, 10
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900}
FP_PERCENT = 3.0  # share of normal training flows allowed above the alert line (same as the deployed model)


def read_day(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    return df


def to_features(df: pd.DataFrame) -> pd.DataFrame:
    """Dataset columns -> our feature columns, plus Label and (when present) the columns the rules need."""
    out = pd.DataFrame(index=df.index)
    for name, (col, div) in FEATURE_MAP.items():
        out[name] = pd.to_numeric(df[col], errors="coerce") / div
    out["label"] = df["Label"].astype(str).str.strip()
    out["label"] = out["label"].str.replace(r"Web Attack.*?(Brute Force|XSS|Sql Injection)", r"Web Attack \1", regex=True)
    out["label"] = out["label"].str.replace(r"[^\x00-\x7f]", "", regex=True).str.replace("Web Attack  ", "Web Attack ")

    has_hosts = {"Source IP", "Destination IP", "Destination Port", "Timestamp"} <= set(df.columns)
    if has_hosts:
        minute = pd.to_datetime(df["Timestamp"], errors="coerce").dt.floor("min")
        src, dst = df["Source IP"], df["Destination IP"]
        dport = pd.to_numeric(df["Destination Port"], errors="coerce")
        key = [src, minute]
        out["uniq_dst_ports_60s"] = df.groupby(key)["Destination Port"].transform("nunique")
        out["uniq_dst_ips_60s"] = df.groupby(key)["Destination IP"].transform("nunique")
        proto = pd.to_numeric(df.get("Protocol", 6), errors="coerce")
        login = (proto == 6) & dport.isin(AUTH_PORTS) & (out["fwd_packets"] >= 3) & (out["bwd_packets"] >= 3) & (out["duration_s"] <= 15)
        out["login_attempts_min"] = login.astype(int).groupby([src, dport, minute]).transform("sum")
        out["_login"] = login
    else:
        out["uniq_dst_ports_60s"] = 0.0
        out["uniq_dst_ips_60s"] = 0.0
        out["login_attempts_min"] = 0
        out["_login"] = False
    out["has_hosts"] = has_hosts
    out = out.replace([np.inf, -np.inf], np.nan).dropna(subset=FLOW_FEATURES)
    out[FLOW_FEATURES] = out[FLOW_FEATURES].clip(lower=0)
    return out


def rule_flags(df: pd.DataFrame) -> pd.Series:
    scan = df["uniq_dst_ports_60s"] >= SCAN_PORTS
    sweep = df["uniq_dst_ips_60s"] >= SWEEP_HOSTS
    brute = df["_login"] & (df["login_attempts_min"] >= BRUTE_PER_MINUTE)
    return scan | sweep | brute


def cap_per_label(df: pd.DataFrame, per_label: int, seed: int) -> pd.DataFrame:
    parts = [g.sample(min(len(g), per_label), random_state=seed) for _, g in df.groupby("label")]
    return pd.concat(parts) if parts else df


def calibrated_threshold(model: IsolationForest, x_train: np.ndarray) -> float:
    return float(np.percentile(model.decision_function(x_train), FP_PERCENT))


def evaluate(data_dir: Path, train_day: str, max_train: int, per_label: int, seed: int = 42) -> dict:
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise SystemExit(f"No CSV files found in {data_dir}")
    frames = {}
    for path in files:
        print(f"reading {path.name} ...", file=sys.stderr)
        frames[path.name] = to_features(read_day(path))

    train_files = [n for n in frames if n.lower().startswith(train_day.lower())]
    if not train_files:
        raise SystemExit(f"No file starting with '{train_day}' found. Files: {', '.join(frames)}")
    train = pd.concat([frames[n] for n in train_files])
    train = train[train["label"].str.upper() == "BENIGN"]
    if len(train) > max_train:
        train = train.sample(max_train, random_state=seed)
    test = pd.concat([f for n, f in frames.items() if n not in train_files])
    test = cap_per_label(test, per_label, seed)
    has_hosts = bool(train["has_hosts"].iloc[0]) if len(train) else False
    features = FLOW_FEATURES + (HOST_FEATURES if has_hosts else [])

    x_train = np.log1p(train[features].to_numpy(dtype=float))
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1).fit(x_train)
    threshold = calibrated_threshold(model, x_train)

    x_test = np.log1p(test[features].to_numpy(dtype=float))
    anomaly = -model.decision_function(x_test)  # higher = more unusual
    flagged = model.decision_function(x_test) < threshold
    ruled = rule_flags(test).to_numpy() if has_hosts else np.zeros(len(test), dtype=bool)
    labels = test["label"].to_numpy()
    benign = np.char.upper(labels.astype(str)) == "BENIGN"

    rows = []
    for label in sorted(set(labels[~benign])):
        sel = labels == label
        auc = roc_auc_score(np.r_[np.zeros(benign.sum()), np.ones(sel.sum())], np.r_[anomaly[benign], anomaly[sel]])
        rows.append({
            "label": label, "flows": int(sel.sum()),
            "model": float(flagged[sel].mean()), "rules": float(ruled[sel].mean()),
            "either": float((flagged | ruled)[sel].mean()), "auc": float(auc),
        })
    return {
        "mode": "full (host features and rules)" if has_hosts else "flow-only (no IP or timestamp columns)",
        "train_flows": int(len(train)), "train_files": train_files, "benign_test": int(benign.sum()),
        "fpr_model": float(flagged[benign].mean()), "fpr_rules": float(ruled[benign].mean()),
        "fpr_either": float((flagged | ruled)[benign].mean()), "rows": rows,
    }


def render(res: dict) -> str:
    pct = lambda v: f"{v:.1%}"  # noqa: E731
    lines = [
        "# Evaluation on CIC-IDS2017 (offline, indicative)",
        "",
        f"Generated on {date.today().isoformat()} by `ml/scripts/eval_cicids.py`. Mode: **{res['mode']}**.",
        "",
        f"The model was trained on {res['train_flows']:,} normal flows from {', '.join(res['train_files'])}, "
        f"with the same settings as the deployed model (log scale, 200 trees, alert line so that about {FP_PERCENT:.0f}% of "
        "normal training flows are flagged). It was tested on the other days.",
        "",
        "## Results",
        "",
        "| Attack type | Test flows | Flagged by model | Flagged by rules | Flagged by either | Model AUC |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for r in res["rows"]:
        lines.append(f"| {r['label']} | {r['flows']:,} | {pct(r['model'])} | {pct(r['rules'])} | {pct(r['either'])} | {r['auc']:.3f} |")
    lines += [
        f"| **Normal traffic (false alarms)** | {res['benign_test']:,} | {pct(res['fpr_model'])} | {pct(res['fpr_rules'])} | {pct(res['fpr_either'])} | |",
        "",
        "AUC is the chance that the model scores a random attack flow as more unusual than a random normal flow "
        "(0.5 = guessing, 1.0 = perfect). It does not depend on the alert line.",
        "",
        "## How to read this honestly",
        "",
        "- The dataset was produced with CICFlowMeter. Packet lengths, flag counts and flow timeouts are computed differently "
        "from our own sensor, so these numbers are indicative, not a measurement of the live sensor.",
        "- The labelled files have timestamps with one-minute resolution, so the \"60 second\" host counts use the minute each flow "
        "started in (a tumbling window), not the sliding window the live system uses.",
        "- Only rules that work on one flow plus a per-minute count were evaluated: port scan, host sweep and password guessing. "
        "The SYN-flood and beaconing rules need packet timing that the CSV files do not contain.",
        "- The model learns from Monday only. Attacks that look like normal traffic (for example web attacks and slow attacks) are "
        "expected to be missed by a flow-statistics model, and the table shows this where it happens.",
        "- Published analyses of CIC-IDS2017 report labelling and flow-construction errors in the dataset.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, required=True, help="folder with the CIC-IDS2017 per-day CSV files")
    ap.add_argument("--out", type=Path, default=Path("docs/EVALUATION_CICIDS2017.md"))
    ap.add_argument("--train-day", default="Monday", help="file name prefix of the all-normal day used for training")
    ap.add_argument("--max-train", type=int, default=300_000, help="most normal flows used for training")
    ap.add_argument("--per-label", type=int, default=50_000, help="most test flows kept per label (saves memory)")
    args = ap.parse_args()

    res = evaluate(args.data, args.train_day, args.max_train, args.per_label)
    report = render(res)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)
    print(report)
    print(f"Report written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
