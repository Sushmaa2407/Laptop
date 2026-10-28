import random
import uuid

import pytest

from app.detection import drift

T, A = uuid.uuid4(), uuid.uuid4()
NOW = 1_800_000_000.0


class FakeRedis:
    """Just enough of the Redis API used by drift.py, so the tests need no server."""

    def __init__(self):
        self.hashes, self.values = {}, {}

    def pipeline(self):
        outer, ops = self, []

        class Pipe:
            def hincrby(self, key, field, n):
                ops.append(("hincrby", key, field, n))

            def expire(self, key, ttl):
                ops.append(("expire", key))

            def hgetall(self, key):
                ops.append(("hgetall", key))

            async def execute(self):
                out = []
                for op in ops:
                    if op[0] == "hincrby":
                        h = outer.hashes.setdefault(op[1], {})
                        h[op[2]] = h.get(op[2], 0) + op[3]
                    out.append(dict(outer.hashes.get(op[1], {})) if op[0] == "hgetall" else None)
                return out

        return Pipe()

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, ex=None):
        self.values[key] = value


async def seed(r, rng, n, now, low=0.0, high=0.3):
    await drift.record(r, T, A, [rng.uniform(low, high) for _ in range(n)], now)


def test_js_divergence_basics():
    same = [5, 3, 2, 0, 0, 0, 0, 0, 0, 0]
    assert drift.js_divergence(same, same) == 0.0
    assert drift.js_divergence([1] + [0] * 9, [0] * 9 + [1]) == pytest.approx(1.0)
    assert drift.js_divergence([1, 2] + [0] * 8, [2, 1] + [0] * 8) == drift.js_divergence([2, 1] + [0] * 8, [1, 2] + [0] * 8)
    assert drift.js_divergence([0] * 10, same) == 0.0


def test_bins_and_labels():
    assert drift.score_bin(0.0) == 0 and drift.score_bin(0.55) == 5 and drift.score_bin(1.0) == 9
    assert drift.describe(0.02) == "close to usual" and drift.describe(0.5) == "very different from usual"


async def test_no_history_means_no_claim():
    assert await drift.compute(FakeRedis(), T, A, NOW) == 0.0


async def test_same_behaviour_is_low_drift():
    r, rng = FakeRedis(), random.Random(1)
    for hours_ago in range(2, 20):  # baseline: 18 hours of usual traffic
        await seed(r, rng, 40, NOW - hours_ago * 3600)
    await seed(r, rng, 120, NOW - 300)  # recent, same shape
    assert await drift.compute(r, T, A, NOW) < 0.05


async def test_changed_behaviour_is_high_drift():
    r, rng = FakeRedis(), random.Random(2)
    for hours_ago in range(2, 20):
        await seed(r, rng, 40, NOW - hours_ago * 3600)
    await seed(r, rng, 120, NOW - 300, low=0.7, high=1.0)  # recent traffic looks very unusual
    assert await drift.compute(r, T, A, NOW) > 0.5


async def test_too_little_data_on_either_side_gives_zero():
    r, rng = FakeRedis(), random.Random(3)
    await seed(r, rng, 100, NOW - 5 * 3600)  # baseline too small
    await seed(r, rng, 120, NOW - 300, low=0.7, high=1.0)
    assert await drift.compute(r, T, A, NOW) == 0.0
