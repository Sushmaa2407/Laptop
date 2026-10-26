import numpy as np

from app.detection.temporal import IGNORED_PORTS, MIN_EVENTS, analyze

T0 = 1.8e9


def periodic(period, n, jitter=0.0, seed=1):
    rng = np.random.default_rng(seed)
    return list(T0 + np.arange(n) * period + rng.uniform(-jitter, jitter, n) * period)


def test_regular_beacon_is_found_with_its_period():
    res = analyze(periodic(10, 20))
    assert res.is_periodic and res.period_s == 10.0 and res.score > 0.8


def test_beacon_with_some_jitter_is_still_found():
    assert all(analyze(periodic(30, 20, 0.1, seed)).is_periodic for seed in range(10))


def test_random_traffic_is_not_periodic():
    rng = np.random.default_rng(5)
    flagged = sum(analyze(list(T0 + np.sort(rng.uniform(0, 600, 40)))).is_periodic for _ in range(200))
    assert flagged <= 2


def test_too_few_events_or_too_short_a_span():
    assert not analyze(periodic(10, MIN_EVENTS - 1)).is_periodic
    assert not analyze(periodic(2, 20)).is_periodic  # 38 s span


def test_normal_periodic_ports_are_excluded():
    assert {53, 123, 5353} <= IGNORED_PORTS
