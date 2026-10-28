"""Temporal layer: does a machine contact the same service at regular intervals? (typical of malware "beaconing")

Method (all on timestamps of flow starts for one source, destination and port):
1. Put the events into 1-second bins and smooth them a little so small timing jitter does not matter.
2. Compute the autocorrelation with the FFT (Wiener-Khinchin: inverse FFT of the power spectrum).
3. The strongest autocorrelation peak at a lag of at least MIN_PERIOD_S is the likely period; its height (0 to 1) is
   the periodicity score. Random traffic has no strong peak; a regular check-in has one at its interval.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

MIN_EVENTS = 8  # need at least this many contacts
MIN_SPAN_S = 60.0  # ... spread over at least this long
MAX_WINDOW_S = 1800  # look back 30 minutes
MIN_PERIOD_S = 3
MAX_PERIOD_S = 600
PERIODIC_SCORE = 0.6  # autocorrelation peak needed to call it periodic
SMOOTHING_WIDTHS = (3, 5, 9, 15, 25)  # seconds
# Ports whose regular traffic is normal (DNS, DHCP, NTP, mDNS, NetBIOS, SSDP): never reported.
IGNORED_PORTS = frozenset({53, 67, 68, 123, 137, 138, 1900, 5353})


@dataclass(frozen=True)
class TemporalResult:
    events: int
    period_s: float
    score: float  # 0..1
    is_periodic: bool


NOT_PERIODIC = TemporalResult(0, 0.0, 0.0, False)


def analyze(timestamps: list[float]) -> TemporalResult:
    ts = np.sort(np.asarray(timestamps, dtype=np.float64))
    n = int(ts.size)
    if n < MIN_EVENTS:
        return TemporalResult(n, 0.0, 0.0, False)
    ts = ts[ts >= ts[-1] - MAX_WINDOW_S]
    n = int(ts.size)
    span = float(ts[-1] - ts[0])
    if n < MIN_EVENTS or span < MIN_SPAN_S:
        return TemporalResult(n, 0.0, 0.0, False)

    size = int(span) + 1
    base = np.zeros(size)
    np.add.at(base, (ts - ts[0]).astype(int), 1.0)

    # Real beacons are rarely exact (they add random delay), so try several smoothing widths and keep the best:
    # a wider window tolerates more jitter but is only allowed to judge periods at least twice as long.
    best_lag, best_score = 0, 0.0
    for width in SMOOTHING_WIDTHS:
        lo, hi = max(MIN_PERIOD_S, 2 * width), min(MAX_PERIOD_S, size // 2)
        if hi <= lo:
            continue
        x = np.convolve(base, np.ones(width), mode="same")
        x -= x.mean()
        spectrum = np.fft.rfft(x, n=2 * size)  # zero-padded: no wrap-around
        ac = np.fft.irfft(spectrum * np.conj(spectrum))[:size]
        if ac[0] <= 1e-12:
            continue
        ac = ac / ac[0]
        lag = lo + int(np.argmax(ac[lo : hi + 1]))
        peak = float(ac[lag])
        # prefer the shortest lag that is almost as strong (a 10 s beat also peaks at 20 s, 30 s ...)
        for cand in range(lo, lag):
            if ac[cand] >= 0.85 * peak and ac[cand] >= ac[cand - 1] and ac[cand] >= ac[cand + 1]:
                lag, peak = cand, float(ac[cand])
                break
        if peak > best_score:
            best_lag, best_score = lag, peak
    score = float(min(1.0, max(0.0, best_score)))
    # The strongest peak can sit on a multiple of the real beat (30 s for a 15 s beat). The typical gap between
    # consecutive events tells which fraction of the peak lag is the true period.
    median_gap = float(np.median(np.diff(ts)))
    if best_lag and median_gap > 0:
        candidate = min((best_lag / k for k in (1, 2, 3, 4)), key=lambda c: abs(c - median_gap))
        if abs(candidate - median_gap) / median_gap < 0.3:
            best_lag = candidate
    return TemporalResult(n, round(float(best_lag), 1), round(score, 3), score >= PERIODIC_SCORE)
