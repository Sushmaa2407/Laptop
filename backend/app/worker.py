"""Detection worker: reads flow batches from the Redis stream, scores them, applies rules, stores flows and alerts.

Run:  python -m app.worker
Environment: DATABASE_URL, REDIS_URL (as the API), SHIELD_MODEL_PATH, SHIELD_MODEL_META (optional).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import signal
import uuid
from collections import Counter

from redis.exceptions import RedisError, ResponseError

from app.db.session import get_sessionmaker
from app.detection import queue
from app.detection.evidence import ANOMALY_ONLY_MIN_SCORE, build_evidence, decide_severity
from app.detection import drift, temporal
from app.detection.rules import BEACONING, BRUTE_FORCE, SYN_FLOOD, RuleHit, check_flow, is_half_open, is_login_attempt
from app.detection.scorer import OnnxScorer
from app.repositories import detection as detection_repo

log = logging.getLogger("shield.worker")

DEDUPE_SECONDS = 300  # one alert per (agent, source address) per 5 minutes
HALF_OPEN_WINDOW_SECONDS = 10
ATTEMPT_WINDOW_SECONDS = 60
BEACON_DEDUPE_SECONDS = 3600  # one beaconing alert per source, destination and port per hour
BEACON_MAX_KEYS_PER_BATCH = 200
IDLE_RECLAIM_MS = 60_000


def _in_allowlist(ip: str, networks: list) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks if net.version == addr.version)


def _extras(hit, half_open: int, attempts: int) -> dict[str, float]:
    """Measured rates that explain a rate-based rule hit (shown as evidence)."""
    if hit and hit.category == SYN_FLOOD:
        return {"half_open_10s": half_open}
    if hit and hit.category == BRUTE_FORCE:
        return {"repeat_connections_60s": attempts}
    return {}


async def _beacons(r, tenant_id, agent_id, flows: list[dict], allow_nets: list) -> list[tuple[int, temporal.TemporalResult]]:
    """Record when each (source, destination, port) was contacted and look for a regular rhythm.

    Returns (index of the newest flow in this batch, result) for every key that now looks periodic.
    """
    groups: dict[tuple, list[int]] = {}
    for i, f in enumerate(flows):
        if f["protocol"] not in ("tcp", "udp") or f["dst_port"] in temporal.IGNORED_PORTS:
            continue
        if _in_allowlist(f["src_ip"], allow_nets) or _in_allowlist(f["dst_ip"], allow_nets):
            continue
        groups.setdefault((f["src_ip"], f["dst_ip"], f["protocol"], f["dst_port"]), []).append(i)

    found = []
    for (src, dst, proto, dport), idxs in list(groups.items())[:BEACON_MAX_KEYS_PER_BATCH]:
        key = f"shield:beacon:{tenant_id}:{agent_id}:{src}:{dst}:{proto}:{dport}"
        newest = max(f["start_ts"] for f in (flows[i] for i in idxs))
        pipe = r.pipeline()
        pipe.zadd(key, {flows[i]["flow_id"]: flows[i]["start_ts"] for i in idxs})
        pipe.zremrangebyscore(key, "-inf", newest - temporal.MAX_WINDOW_S)
        pipe.expire(key, temporal.MAX_WINDOW_S + 600)
        pipe.zcard(key)
        count = (await pipe.execute())[-1]
        if count < temporal.MIN_EVENTS:
            continue
        stamps = [score for _member, score in await r.zrange(key, 0, -1, withscores=True)]
        result = temporal.analyze(stamps)
        if result.is_periodic:
            found.append((max(idxs, key=lambda i: flows[i]["start_ts"]), result))
    return found


def _add_alert(session, tenant_id, agent_id, scorer, flow, score, hit, severity, dedupe_key, extras, temporal_result=None,
               drift_value=0.0):
    alert_id = uuid.uuid4()
    evidence = build_evidence(alert_id=alert_id, flow=flow, hit=hit, score=score, threshold=scorer.threshold,
                              model_version=scorer.model_version, severity=severity, extras=extras, temporal=temporal_result, drift=drift_value)
    detection_repo.add_alert(session, tenant_id, alert_id=alert_id, agent_id=agent_id, flow_id=uuid.UUID(flow["flow_id"]),
                             severity=severity, dedupe_key=dedupe_key, evidence=evidence.model_dump(mode="json"))
    return alert_id


async def process_batch(r, scorer: OnnxScorer, payload: dict) -> int:
    """Score, store and raise alerts for one batch. Returns the number of alerts created."""
    tenant_id = uuid.UUID(payload["tenant_id"])
    agent_id = uuid.UUID(payload["agent_id"])
    flows: list[dict] = payload["flows"]
    scores = scorer.score_records(flows)
    await drift.record(r, tenant_id, agent_id, scores)
    drift_value = await drift.compute(r, tenant_id, agent_id)

    # --- how many half-open flows did each source create in the last 10 s (SYN flood signal)?
    per_src = Counter(f["src_ip"] for f in flows if is_half_open(f))
    half_open: dict[str, int] = {}
    for src, n in per_src.items():
        key = f"shield:half_open:{tenant_id}:{agent_id}:{src}"
        pipe = r.pipeline()
        pipe.incrby(key, n)
        pipe.expire(key, HALF_OPEN_WINDOW_SECONDS, nx=True)
        half_open[src] = (await pipe.execute())[0]

    # --- how many login-style connections did each source make to each login service in the last 60 s?
    per_target = Counter((f["src_ip"], f["dst_port"]) for f in flows if is_login_attempt(f))
    attempts: dict[tuple[str, int], int] = {}
    for (src, dport), n in per_target.items():
        key = f"shield:attempts:{tenant_id}:{agent_id}:{src}:{dport}"
        pipe = r.pipeline()
        pipe.incrby(key, n)
        pipe.expire(key, ATTEMPT_WINDOW_SECONDS, nx=True)
        attempts[(src, dport)] = (await pipe.execute())[0]

    created = 0
    async with get_sessionmaker()() as session:
        rows = [{**f, "anomaly_score": s} for f, s in zip(flows, scores, strict=True)]
        for row in rows:
            row["flow_id"] = uuid.UUID(row["flow_id"])
        await detection_repo.insert_flows(session, tenant_id, agent_id, rows)

        allow_nets = [ipaddress.ip_network(c, strict=False) for c in await detection_repo.allowlist_cidrs(session, tenant_id)]
        new_alert_ids: list[uuid.UUID] = []
        # Strongest flows first, so the alert for a source shows its most telling flow (e.g. the highest port count).
        order = sorted(range(len(flows)), key=lambda i: (flows[i]["uniq_dst_ports_60s"], flows[i]["uniq_dst_ips_60s"],
                                                         scores[i]), reverse=True)
        for i in order:
            flow, score = flows[i], scores[i]
            src = flow["src_ip"]
            if _in_allowlist(src, allow_nets):
                continue
            hit = check_flow(flow, half_open.get(src, 0), attempts.get((src, flow["dst_port"]), 0))
            anomalous = score >= scorer.threshold
            if not hit and not (anomalous and score >= ANOMALY_ONLY_MIN_SCORE):
                continue
            severity = decide_severity(hit, anomalous)
            if severity is None:
                continue
            dedupe_key = src  # one alert per source address per 5 minutes, whatever the kind
            claimed = await r.set(f"shield:dedupe:{tenant_id}:{agent_id}:{dedupe_key}", "1", ex=DEDUPE_SECONDS, nx=True)
            if not claimed:
                continue
            alert_id = _add_alert(session, tenant_id, agent_id, scorer, flow, score, hit, severity, dedupe_key,
                                  _extras(hit, half_open.get(src, 0), attempts.get((src, flow["dst_port"]), 0)), None, drift_value)
            new_alert_ids.append(alert_id)
            created += 1

        # --- temporal layer: regular check-ins of one machine with one address and port
        for i, result in await _beacons(r, tenant_id, agent_id, flows, allow_nets):
            flow, score = flows[i], scores[i]
            hit = RuleHit(BEACONING, False)
            severity = decide_severity(hit, score >= scorer.threshold)
            dedupe_key = f"{flow['src_ip']}>{flow['dst_ip']}:{flow['dst_port']}"
            if not await r.set(f"shield:dedupe:{tenant_id}:{agent_id}:beacon:{dedupe_key}", "1",
                               ex=BEACON_DEDUPE_SECONDS, nx=True):
                continue
            alert_id = _add_alert(session, tenant_id, agent_id, scorer, flow, score, hit, severity, dedupe_key,
                                  {"beacon_period_s": result.period_s, "beacon_events": result.events}, result, drift_value)
            new_alert_ids.append(alert_id)
            created += 1
        await session.commit()

    for alert_id in new_alert_ids:  # queue for the LLM explainer (Batch 3)
        await r.xadd(queue.ALERT_STREAM, {"tenant_id": str(tenant_id), "alert_id": str(alert_id)},
                     maxlen=10_000, approximate=True)
        log.info("alert %s created", alert_id)
    return created


async def handle(r, scorer: OnnxScorer, msg_id: str, fields: dict) -> None:
    try:
        await process_batch(r, scorer, json.loads(fields["d"]))
    except RedisError:
        raise  # transient: leave the batch unacknowledged, it is picked up again shortly
    except Exception:  # noqa: BLE001 - a bad batch must never stop the worker
        log.exception("batch %s failed; moved to dead list", msg_id)
        await r.lpush(queue.DEAD_LIST, fields.get("d", ""))
        await r.ltrim(queue.DEAD_LIST, 0, 99)
    await r.xack(queue.FLOW_STREAM, queue.FLOW_GROUP, msg_id)


async def run(stop: asyncio.Event | None = None) -> None:
    stop = stop or asyncio.Event()
    model_path = os.environ.get("SHIELD_MODEL_PATH", "/ml/models/shield_iforest.onnx")
    meta_path = os.environ.get("SHIELD_MODEL_META", model_path.rsplit(".", 1)[0] + ".json")
    scorer = OnnxScorer(model_path, meta_path)
    log.info("model %s loaded (threshold %.2f)", scorer.model_version, scorer.threshold)

    r = queue.get_redis()
    try:
        await r.xgroup_create(queue.FLOW_STREAM, queue.FLOW_GROUP, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    consumer = f"worker-{os.getpid()}"

    while not stop.is_set():
        try:
            await _step(r, scorer, consumer)
        except ResponseError as exc:  # e.g. the stream or group vanished (Redis was reset): recreate and go on
            log.warning("redis stream problem (%s); recreating group", exc)
            try:
                await r.xgroup_create(queue.FLOW_STREAM, queue.FLOW_GROUP, id="0", mkstream=True)
            except ResponseError:
                pass
        except (RedisError, OSError) as exc:  # timeouts, dropped connections, restarts: wait and retry
            log.warning("redis problem (%s); retrying", exc)
            await asyncio.sleep(2)


async def _step(r, scorer: OnnxScorer, consumer: str) -> None:
    # take over batches another (crashed) worker started but never finished
    try:
        _next, claimed, *_ = await r.xautoclaim(queue.FLOW_STREAM, queue.FLOW_GROUP, consumer, IDLE_RECLAIM_MS,
                                                start_id="0-0", count=10)
        for msg_id, fields in claimed:
            if fields:
                await handle(r, scorer, msg_id, fields)
    except ResponseError as exc:
        if "NOGROUP" in str(exc):
            raise
    resp = await r.xreadgroup(queue.FLOW_GROUP, consumer, {queue.FLOW_STREAM: ">"}, count=20, block=2000)
    for _stream, messages in resp or []:
        for msg_id, fields in messages:
            await handle(r, scorer, msg_id, fields)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    loop = asyncio.new_event_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    loop.run_until_complete(run(stop))


if __name__ == "__main__":
    main()
