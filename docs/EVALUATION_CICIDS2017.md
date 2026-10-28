# Evaluation on CIC-IDS2017 (offline, indicative)

Generated on 2026-10-28 by `ml/scripts/eval_cicids.py`. Mode: **full (host features and rules)**.

The model was trained on 300,000 normal flows from Monday-WorkingHours.pcap_ISCX.csv, with the same settings as the deployed model (log scale, 200 trees, alert line so that about 3% of normal training flows are flagged). It was tested on the other days.

## Results

| Attack type | Test flows | Flagged by model | Flagged by rules | Flagged by either | Model AUC |
|---|---:|---:|---:|---:|---:|
| Bot | 1,966 | 2.0% | 32.2% | 33.7% | 0.597 |
| DDoS | 50,000 | 18.6% | 0.0% | 18.6% | 0.901 |
| DoS GoldenEye | 10,293 | 28.3% | 30.2% | 52.7% | 0.944 |
| DoS Hulk | 50,000 | 61.3% | 0.0% | 61.3% | 0.862 |
| DoS Slowhttptest | 5,499 | 88.3% | 65.6% | 92.1% | 0.978 |
| DoS slowloris | 5,796 | 56.1% | 22.0% | 62.9% | 0.932 |
| FTP-Patator | 7,938 | 0.0% | 50.0% | 50.0% | 0.845 |
| Heartbleed | 11 | 100.0% | 0.0% | 100.0% | 0.999 |
| Infiltration | 36 | 83.3% | 63.9% | 88.9% | 0.946 |
| PortScan | 50,000 | 0.2% | 99.8% | 99.8% | 0.858 |
| SSH-Patator | 5,897 | 10.3% | 50.8% | 51.2% | 0.698 |
| Web Attack Brute Force | 1,507 | 4.9% | 0.0% | 4.9% | 0.868 |
| Web Attack Sql Injection | 21 | 0.0% | 0.0% | 0.0% | 0.687 |
| Web Attack XSS | 652 | 2.6% | 0.0% | 2.6% | 0.900 |
| **Normal traffic (false alarms)** | 50,000 | 5.4% | 55.6% | 57.0% | |

AUC is the chance that the model scores a random attack flow as more unusual than a random normal flow (0.5 = guessing, 1.0 = perfect). It does not depend on the alert line.

## How to read this honestly

- The dataset was produced with CICFlowMeter. Packet lengths, flag counts and flow timeouts are computed differently from our own sensor, so these numbers are indicative, not a measurement of the live sensor.
- The labelled files have timestamps with one-minute resolution, so the "60 second" host counts use the minute each flow started in (a tumbling window), not the sliding window the live system uses.
- Only rules that work on one flow plus a per-minute count were evaluated: port scan, host sweep and password guessing. The SYN-flood and beaconing rules need packet timing that the CSV files do not contain.
- The model learns from Monday only. Attacks that look like normal traffic (for example web attacks and slow attacks) are expected to be missed by a flow-statistics model, and the table shows this where it happens.
- Published analyses of CIC-IDS2017 report labelling and flow-construction errors in the dataset.
