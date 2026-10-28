# Temporal layer: detecting regular check-ins (beaconing)

## What it looks for
A machine that contacts the same address and port again and again at a steady rhythm, for example every 10 or 30 seconds. Malware often does this to ask its controller for orders. Normal browsing is irregular.

## How it works
1. For every flow, the worker stores its start time under the key (source, destination, protocol, port) in Redis, keeping the last 30 minutes.
2. Once a key has at least 8 contacts spread over at least 60 seconds, the timestamps are put into 1-second bins and lightly smoothed (several smoothing widths are tried, so small timing jitter is tolerated).
3. The autocorrelation of that signal is computed with the FFT (inverse FFT of the power spectrum). A strong peak at some lag means the contacts repeat with that period. The peak height (0 to 1) is the periodicity score; 0.6 or more counts as periodic.
4. The reported period is checked against the typical gap between contacts, so a 15-second rhythm is not reported as 30 seconds.
5. A periodic key raises one "Regular check-ins" alert per hour. The alert shows the period, the number of contacts and the score. Blocking it cuts off the remote address, not the protected machine.
Traffic on DNS, DHCP, NTP, mDNS, NetBIOS and SSDP ports is ignored because it is regular by nature.

## Measured on simulated timestamps (not real traffic)
| Case | Result |
|---|---|
| Exact rhythm, periods 10 to 120 s | detected 100% |
| Rhythm with up to 10% random timing jitter, periods 10 to 60 s | detected about 87 to 100% |
| Rhythm with 20% jitter or more | mostly missed (under 10%) |
| 6,000 random sequences (steady random traffic, dense traffic, bursty browsing) | 0 false alarms |
Parameters and the simulation are in `backend/app/detection/temporal.py` and `backend/tests/test_temporal.py`. These numbers describe the method on generated data. Real traffic will behave differently.

## Limits to state honestly
- Legitimate software that checks in regularly (update checkers, health checks, monitoring) looks the same, so a person decides.
- Beacons with more than about 15% random delay are missed.
- Baseline drift (the other field of the timing section of the evidence) is computed separately in `backend/app/detection/drift.py`: it compares the last 30 minutes of anomaly scores with the previous day for the same device, and stays 0 until there is enough history.
