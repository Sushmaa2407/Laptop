"""Baseline drift: how different is this machine's recent traffic from its own usual traffic?

Every scored flow adds one count to a 10-bin histogram of anomaly scores, kept per agent in 10-minute buckets
for 26 hours. "Recent" is the last 30 minutes; the baseline is everything from 30 minutes to 24 hours ago.
Drift is the Jensen-Shannon divergence between the two histograms, scaled to 0..1 (0 = same shape, 1 = nothing in common).
Too little data on either side gives 0 (we do not guess).
"""

from __future__ import annotations

import math
import time

BINS = 10
BUCKET_S = 600
RECENT_BUCKETS = 3  # 30 minutes
BASELINE_BUCKETS = 144  # 24 hours
TTL_S = 26 * 3600
MIN_RECENT = 50  # flows
MIN_BASELINE = 300  # flows
CACHE_S = 60


def score_bin(score: float) -> int:
    return min(BINS - 1, max(0, int(score * BINS)))


def js_divergence(p: list[float], q: list[float]) -> float:
    """Jensen-Shannon divergence in bits, 0..1. p and q are counts (they are normalised here)."""
    sp, sq = sum(p), sum(q)
    if sp <= 0 or sq <= 0:
        return 0.0
    p = [x / sp for x in p]
    q = [x / sq for x in q]
    m = [(a + b) / 2 for a, b in zip(p, q, strict=True)]

    def kl(a: list[float], b: list[float]) -> float:
        return sum(x * math.log2(x / y) for x, y in zip(a, b, strict=True) if x > 0)

    return max(0.0, min(1.0, (kl(p, m) + kl(q, m)) / 2))


def _key(tenant_id, agent_id, bucket: int) -> str:
    return f"shield:drift:{tenant_id}:{agent_id}:{bucket}"


async def record(r, tenant_id, agent_id, scores: list[float], now: float | None = None) -> None:
    if not scores:
        return
    key = _key(tenant_id, agent_id, int((now if now is not None else time.time()) // BUCKET_S))
    counts: dict[int, int] = {}
    for s in scores:
        b = score_bin(s)
        counts[b] = counts.get(b, 0) + 1
    pipe = r.pipeline()
    for b, n in counts.items():
        pipe.hincrby(key, str(b), n)
    pipe.expire(key, TTL_S)
    await pipe.execute()


async def _histogram(r, tenant_id, agent_id, buckets: range) -> list[float]:
    pipe = r.pipeline()
    for b in buckets:
        pipe.hgetall(_key(tenant_id, agent_id, b))
    total = [0.0] * BINS
    for h in await pipe.execute():
        for field, value in h.items():
            total[int(field)] += float(value)
    return total


async def compute(r, tenant_id, agent_id, now: float | None = None) -> float:
    """Current drift for one agent (cached for a minute)."""
    cache_key = f"shield:drift:value:{tenant_id}:{agent_id}"
    cached = await r.get(cache_key)
    if cached is not None:
        return float(cached)
    current_bucket = int((now if now is not None else time.time()) // BUCKET_S)
    recent = await _histogram(r, tenant_id, agent_id, range(current_bucket - RECENT_BUCKETS + 1, current_bucket + 1))
    baseline = await _histogram(r, tenant_id, agent_id,
                                range(current_bucket - RECENT_BUCKETS - BASELINE_BUCKETS + 1, current_bucket - RECENT_BUCKETS + 1))
    value = 0.0
    if sum(recent) >= MIN_RECENT and sum(baseline) >= MIN_BASELINE:
        value = round(js_divergence(recent, baseline), 3)
    await r.set(cache_key, value, ex=CACHE_S)
    return value


def describe(drift: float) -> str:
    if drift < 0.1:
        return "close to usual"
    if drift < 0.3:
        return "somewhat different from usual"
    return "very different from usual"
