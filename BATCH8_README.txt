BATCH 8 - distribution (Devices page + installer), baseline drift, CIC-IDS2017 evaluation
Needs batches 1-7 already applied.
1. Unzip at the repo root.
2. Read docs/DISTRIBUTION.md (operator steps) - build the bundle, add the volume line, rebuild.
3. Baseline drift needs no setup (it fills in after the first hour or so of traffic).
4. Evaluation: pip install pandas, download CIC-IDS2017 (see chat), run ml/scripts/eval_cicids.py.
