"""The sensor: capture frames -> parse -> flows -> JSON records -> server.

Two threads so that slow network calls never make us drop packets:
  main thread   reads the socket, assembles flows, puts finished flow records on a queue
  uplink thread sends batches, sends heartbeats, fetches and applies commands
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import uuid
from collections import deque
from pathlib import Path

from shield_agent.client import ApiError, NetworkError, ShieldClient
from shield_agent.config import AGENT_VERSION, AgentConfig, default_state_path
from shield_agent.response import Responder
from shield_agent.sensor.capture import RawCapture, SelfTrafficFilter, local_addresses
from shield_agent.sensor.flows import FlowTable, to_record
from shield_agent.sensor.packet import ParsedPacket, parse_frame

log = logging.getLogger("shield.sensor")

BATCH_MAX = 200  # server accepts up to 500
SEND_EVERY_S = 2.0
HEARTBEAT_EVERY_S = 15.0
COMMANDS_EVERY_S = 3.0
IDLE_TIMEOUT_S = 10.0  # a silent flow is finished (and reported) after this long; keeps alert latency low
BUFFER_MAX_FLOWS = 20_000  # flows kept while the server is unreachable; oldest are dropped first


class Counters:
    def __init__(self) -> None:
        self.started = time.time()
        self.flows_buffer_dropped = 0
        self.parse_skipped = 0


# ---------------------------------------------------------------- uplink (network thread)
class Uplink(threading.Thread):
    def __init__(self, client: ShieldClient, flows_q: queue.Queue, capture: RawCapture, counters: Counters,
                 responder: Responder, stop: threading.Event) -> None:
        super().__init__(name="uplink", daemon=True)
        self._client = client
        self._q = flows_q
        self._capture = capture
        self._counters = counters
        self._responder = responder
        self._stop_evt = stop
        self._buffer: deque[dict] = deque()

    def run(self) -> None:
        last_send = last_hb = last_cmd = 0.0
        while not self._stop_evt.is_set():
            now = time.monotonic()
            self._drain_queue()
            if now - last_send >= SEND_EVERY_S:
                self._flush()
                last_send = now
            if now - last_hb >= HEARTBEAT_EVERY_S:
                self._heartbeat()
                last_hb = now
            if now - last_cmd >= COMMANDS_EVERY_S:
                self._commands()
                last_cmd = now
            self._stop_evt.wait(0.25)
        self._drain_queue()
        self._flush()  # last attempt on shutdown

    def _drain_queue(self) -> None:
        try:
            while True:
                self._buffer.append(self._q.get_nowait())
        except queue.Empty:
            pass
        while len(self._buffer) > BUFFER_MAX_FLOWS:
            self._buffer.popleft()
            self._counters.flows_buffer_dropped += 1

    def _flush(self) -> None:
        while self._buffer:
            batch = [self._buffer[i] for i in range(min(BATCH_MAX, len(self._buffer)))]
            try:
                self._client.send_flows(batch)
            except NetworkError as exc:
                log.warning("server unreachable, keeping %d flows: %s", len(self._buffer), exc)
                return
            except ApiError as exc:
                log.error("server rejected telemetry (%s); dropping %d flows", exc, len(batch))
            for _ in batch:
                self._buffer.popleft()

    def _heartbeat(self) -> None:
        self._capture.refresh_drop_counter()
        payload = {
            "schema_version": 1,
            "agent_version": AGENT_VERSION,
            "platform": "linux",
            "uptime_s": int(time.time() - self._counters.started),
            "packets_seen": self._capture.packets_seen,
            "packets_dropped": self._capture.packets_dropped,
            "flows_buffer_dropped": self._counters.flows_buffer_dropped,
        }
        try:
            self._client.heartbeat(payload)
        except (NetworkError, ApiError) as exc:
            log.warning("heartbeat failed: %s", exc)

    def _commands(self) -> None:
        for ip in self._responder.expire_due():
            log.info("block on %s expired", ip)
        try:
            commands = self._client.pull_commands()
        except (NetworkError, ApiError) as exc:
            log.debug("command poll failed: %s", exc)
            return
        for cmd in commands:
            state, message = self._responder.apply(cmd)
            log.info("command %s %s %s -> %s (%s)", cmd.get("command_id"), cmd.get("type"), cmd.get("ip"), state, message)
            try:
                self._client.ack_command(str(cmd["command_id"]), state, message)
            except (NetworkError, ApiError) as exc:
                log.warning("could not acknowledge command: %s", exc)


# ---------------------------------------------------------------- main loop
def run_sensor(config: AgentConfig, *, record_to: Path | None = None, seconds: float | None = None,
               dry_run_block: bool = False, stop: threading.Event | None = None) -> None:
    """Capture until stopped. With record_to, write flows to a JSONL file instead of contacting the server."""
    stop = stop or threading.Event()
    capture = RawCapture(config.interface)
    capture.open()
    own = SelfTrafficFilter(config.server_url)
    table = FlowTable(idle_timeout=IDLE_TIMEOUT_S)
    counters = Counters()
    flows_q: queue.Queue = queue.Queue(maxsize=100_000)

    uplink = None
    uplink_stop = threading.Event()  # set only AFTER the last flows were queued, so none are lost on shutdown
    out_file = None
    if record_to is not None:
        record_to.parent.mkdir(parents=True, exist_ok=True)
        out_file = record_to.open("a")
        log.info("recording flows to %s", record_to)
    else:
        client = ShieldClient(config.server_url, config.api_key, config.ca_cert)
        responder = Responder(protected=local_addresses() | own.server_addresses, dry_run=dry_run_block,
                              state_path=default_state_path())
        uplink = Uplink(client, flows_q, capture, counters, responder, uplink_stop)
        uplink.start()
        log.info("sensor running, sending to %s", config.server_url)

    def emit(finished) -> None:
        for flow in finished:
            record = to_record(flow, uuid.uuid4())
            if out_file is not None:
                out_file.write(json.dumps(record) + "\n")
            else:
                try:
                    flows_q.put_nowait(record)
                except queue.Full:
                    counters.flows_buffer_dropped += 1

    deadline = time.time() + seconds if seconds else None
    last_expire = time.time()
    try:
        while not stop.is_set():
            item = capture.read()
            now = time.time()
            if item is not None:
                frame, ts = item
                parsed = parse_frame(frame)
                if isinstance(parsed, ParsedPacket):
                    if not own.is_own(parsed):
                        emit(table.process(parsed, ts))
                else:
                    counters.parse_skipped += 1
            if now - last_expire >= 1.0:  # finish idle flows even when the network is quiet
                emit(table.expire(now))
                last_expire = now
            if deadline and now >= deadline:
                break
    except KeyboardInterrupt:
        log.info("stopping")
    finally:
        emit(table.flush_all())
        stop.set()
        uplink_stop.set()
        if uplink is not None:
            uplink.join(timeout=15)
        if out_file is not None:
            out_file.close()
        capture.close()
