# Evaluation on CIC-IDS2017 (offline, indicative)

Generated on 2026-10-28 by `ml/scripts/eval_cicids.py`. Mode: **full (host features and rules)**.

**Endpoint view:** only flows toward 192.168.10.50 were used, which is what a sensor installed on that machine would see. Training and testing use the same view.

The model was trained on 4,230 normal flows from Monday-WorkingHours.pcap_ISCX.csv, with the same settings as the deployed model (log scale, 200 trees, alert line so that about 3% of normal training flows are flagged). It was tested on the other days.

## Results

| Attack type | Test flows | Flagged by model | Flagged by rules | Flagged by either | Model AUC |
|---|---:|---:|---:|---:|---:|
| DDoS | 50,000 | 99.9% | 0.0% | 99.9% | 0.991 |
| DoS GoldenEye | 10,293 | 99.8% | 0.0% | 99.8% | 0.995 |
| DoS Hulk | 50,000 | 72.6% | 0.0% | 72.6% | 0.894 |
| DoS Slowhttptest | 5,499 | 93.9% | 0.0% | 93.9% | 0.988 |
| DoS slowloris | 5,796 | 90.6% | 0.0% | 90.6% | 0.959 |
| FTP-Patator | 7,938 | 50.3% | 50.0% | 50.3% | 0.937 |
| PortScan | 50,000 | 0.9% | 99.8% | 99.9% | 0.685 |
| SSH-Patator | 5,897 | 50.6% | 49.8% | 50.6% | 0.645 |
| Web Attack Brute Force | 1,507 | 90.5% | 0.0% | 90.5% | 0.929 |
| Web Attack Sql Injection | 21 | 57.1% | 0.0% | 57.1% | 0.709 |
| Web Attack XSS | 652 | 96.5% | 0.0% | 96.5% | 0.980 |
| **Normal traffic (false alarms)** | 24,102 | 7.0% | 18.7% | 24.2% | |

Rule false alarms on normal traffic, by rule: port scan 18.7%, host sweep 0.0%, password guessing 0.0%.

AUC is the chance that the model scores a random attack flow as more unusual than a random normal flow (0.5 = guessing, 1.0 = perfect). It does not depend on the alert line.

## How to read this honestly

- The dataset was produced with CICFlowMeter. Packet lengths, flag counts and flow timeouts are computed differently from our own sensor, so these numbers are indicative, not a measurement of the live sensor.
- The labelled files have timestamps with one-minute resolution, so the "60 second" host counts use the minute each flow started in (a tumbling window), not the sliding window the live system uses.
- Only rules that work on one flow plus a per-minute count were evaluated: port scan, host sweep and password guessing. The SYN-flood and beaconing rules need packet timing that the CSV files do not contain.
- The model learns from Monday only. Attacks that look like normal traffic (for example web attacks and slow attacks) are expected to be missed by a flow-statistics model, and the table shows this where it happens.
- Published analyses of CIC-IDS2017 report labelling and flow-construction errors in the dataset.
