"""Explainer worker: for every new alert, ask the local LLM for a plain-English explanation.

Run:  python -m app.explainer
Environment: OLLAMA_URL (default http://host.docker.internal:11434), OLLAMA_MODEL (default llama3.2:3b),
             DATABASE_URL, REDIS_URL as for the API.
If the LLM is unreachable or answers badly, a deterministic template explanation is stored instead
(explanation_status = 'fallback'), so the dashboard always has something to show.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
import uuid

from redis.exceptions import RedisError, ResponseError

from app.db.session import get_sessionmaker
from app.detection import explain, queue
from app.repositories import alerts as alerts_repo

log = logging.getLogger("shield.explainer")
GROUP = "explainers"
IDLE_RECLAIM_MS = 120_000


def settings() -> tuple[str, str]:
    return (os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434"),
            os.environ.get("OLLAMA_MODEL", "llama3.2:3b"))


async def explain_alert(tenant_id: uuid.UUID, alert_id: uuid.UUID) -> str:
    """Produce and store the explanation. Returns 'ready', 'fallback' or 'skipped'."""
    url, model = settings()
    async with get_sessionmaker()() as session:
        alert = await alerts_repo.get_alert(session, tenant_id, alert_id)
        if alert is None or alert.explanation_status != "pending":
            return "skipped"
        evidence = alert.evidence
        severity = alert.severity

        started = time.monotonic()
        status, result, reason = "fallback", None, ""
        try:
            raw = await asyncio.to_thread(explain.ollama_chat, url, model, explain.build_messages(evidence))
            result = explain.parse_llm_answer(raw, severity, evidence)
            status = "ready"
        except (explain.LlmError, ValueError) as exc:
            reason = str(exc)[:200]
            log.warning("alert %s: LLM unusable (%s); using template", alert_id, reason)
            result = explain.template_explanation(evidence)
        result["source"] = "llm" if status == "ready" else "template"
        result["model"] = model if status == "ready" else None
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        if reason:
            result["fallback_reason"] = reason

        await alerts_repo.set_explanation(session, tenant_id, alert_id, explanation=result, status=status)
        await session.commit()
    log.info("alert %s explained (%s, %d ms)", alert_id, status, result["latency_ms"])
    return status


async def _step(r, consumer: str) -> None:
    try:
        _n, claimed, *_ = await r.xautoclaim(queue.ALERT_STREAM, GROUP, consumer, IDLE_RECLAIM_MS, start_id="0-0", count=5)
        for msg_id, fields in claimed:
            await _handle(r, msg_id, fields)
    except ResponseError as exc:
        if "NOGROUP" in str(exc):
            raise
    resp = await r.xreadgroup(GROUP, consumer, {queue.ALERT_STREAM: ">"}, count=1, block=2000)
    for _s, messages in resp or []:
        for msg_id, fields in messages:
            await _handle(r, msg_id, fields)


async def _handle(r, msg_id: str, fields: dict) -> None:
    try:
        await explain_alert(uuid.UUID(fields["tenant_id"]), uuid.UUID(fields["alert_id"]))
    except Exception:  # noqa: BLE001 - leave unacknowledged so it is retried later
        log.exception("explaining %s failed; will retry", msg_id)
        return
    await r.xack(queue.ALERT_STREAM, GROUP, msg_id)


async def run(stop: asyncio.Event | None = None) -> None:
    stop = stop or asyncio.Event()
    url, model = settings()
    log.info("explainer using %s at %s", model, url)

    async def warm() -> None:
        try:
            await asyncio.to_thread(explain.warm_up, url, model)
            log.info("model %s is loaded and ready", model)
        except explain.LlmError as exc:
            log.warning("could not warm up the model (%s); alerts will get template explanations until it is reachable", exc)

    asyncio.create_task(warm())
    r = queue.get_redis()
    try:
        await r.xgroup_create(queue.ALERT_STREAM, GROUP, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    consumer = f"explainer-{os.getpid()}"
    while not stop.is_set():
        try:
            await _step(r, consumer)
        except ResponseError as exc:
            log.warning("redis stream problem (%s); recreating group", exc)
            try:
                await r.xgroup_create(queue.ALERT_STREAM, GROUP, id="0", mkstream=True)
            except ResponseError:
                pass
        except (RedisError, OSError) as exc:  # timeouts, dropped connections, restarts: wait and retry
            log.warning("redis problem (%s); retrying", exc)
            await asyncio.sleep(2)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    loop = asyncio.new_event_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    loop.run_until_complete(run(stop))


if __name__ == "__main__":
    main()
