# Laptop Shield — Master Plan v2 (Solo, Corrected)

**Project:** Laptop Shield — Endpoint Detection & Response (EDR) with human-in-the-loop IPS, delivered as a small multi-tenant SaaS
**Owner:** Cod (solo, final-year B.E. CSE major project)
**Purpose of this file:** the single source of truth for architecture, decisions, plan, and working rules. Re-read it at the start of every development session. Update it whenever a decision changes (see §17).

> **Honest note on "no risks":** no real project has zero risk. This plan removes every flaw found in the v1 documents and the risks we could foresee, and for the ones that remain it gives a mitigation and a fallback (§15). If a new risk shows up, add it there instead of ignoring it.

---

## 0. Current status (update this as you go)

- [ ] Phase 0 — Setup & feasibility spikes
- [ ] Phase 1 — Contracts & foundations
- [ ] Phase 2 — Sensor → ingestion → storage (end-to-end, no detection)
- [ ] Phase 3 — ML pipeline & detection layers
- [ ] Phase 4 — Dashboard & notifications
- [ ] Phase 5 — Enforcement (block/allow loop)
- [ ] Phase 6 — LLM explainer & study module
- [ ] Phase 7 — Evaluation
- [ ] Phase 8 — Hardening, report, demo

**Last session:** _(date, what was done, what's next)_

---

## 1. What changed from the v1 plan (and why)

| # | v1 problem | v2 fix |
|---|-----------|--------|
| 1 | `subprocess.run(..., shell=True)` with an f-string IP → command injection | Argument lists, never a shell; IP validated with `ipaddress`; allow/protect lists; dedicated firewall chain (§8) |
| 2 | "Unprivileged" agent that also edits the firewall (contradiction) | Two processes: **sensor** (only `CAP_NET_RAW`) and **enforcer** (only `CAP_NET_ADMIN`) (§7) |
| 3 | Ingestion endpoint had no authentication; no tenant/agent identity in payload | Per-agent API keys; tenant derived **server-side** from the key (§9) |
| 4 | Redis `rpush` list called a "stream": messages lost on worker crash | Real **Redis Streams** with consumer groups, ack, retry, dead-letter, max length (§10) |
| 5 | Model trained on CICIDS2017's ~78 CICFlowMeter features, but agent sends 11 different ones | One **shared feature module** used by agent, backend, and training; features chosen so they can be computed live (§11) |
| 6 | `hour_sin`/`hour_cos` as model features | **Removed** from the model (CICIDS2017 attacks happened at fixed times → the model would learn the schedule, not the attack) |
| 7 | "Signed" ONNX = a hash stored beside the model | Model **manifest** (hash, feature order, threshold, metrics); manifest hash from environment/secret; model bytes hashed then loaded from memory (no check-then-load gap) (§11.4) |
| 8 | ONNX output read as `outputs[0][0]` (that's the label, not the score) | Select output by name after inspecting the session; normalized score documented (§11.4) |
| 9 | Telegram URL wrong; unauthenticated callback buttons; per-user bot tokens | One project bot; users link via one-time code; alert contains a dashboard link; buttons are optional and use signed single-use tokens (§12) |
| 10 | Compose: DB/Redis ports published, hard-coded password, `--reload`, no TLS | Only Caddy (80/443) exposed; secrets in `.env`; healthchecks; separate dev override (§13) |
| 11 | Sync `ollama.chat` in async code (blocks the server); Llama 3 in an 8 GB budget | `AsyncClient`, small model, timeout, background job, deterministic fallback, output guard (§14) |
| 12 | Pydantic v1 `validator`; IPv6 regex missed `::1`-style forms; no range checks | Pydantic v2, `ipaddress`, bounded fields, `extra="forbid"` (§6) |
| 13 | `requirements.txt` listed `hashlib`, omitted `httpx`, kept `joblib` | Clean, pinned, lock-filed dependencies (§5) |
| 14 | WSL2 as the capture environment (it cannot see Windows host traffic) | Linux VM / native Linux for the agent; Windows service is a stretch goal (§7, §5) |
| 15 | `passlib[bcrypt]` (compat problems with recent `bcrypt`) | `argon2-cffi` directly (§9) |
| 16 | "Cluster plot" claim | It is a **2-D PCA projection** of the feature space, labeled honestly (§12) |
| 17 | Unvalidated evaluation story, "46 tests" claim, stray `[source: 0.6.1]` tags | Defined study protocol + stats; only claim tests that exist (§16) |
| 18 | Scope sized for 4 people | Solo scope with Must/Should/Could tiers and a cut list (§3, §4) |
| 19 | No block safety (false positives could cut the user off) | Never block gateway/DNS/server/private ranges; TTLs; undo; dry-run mode (§8) |
| 20 | No data-retention, privacy or ethics section | Added (§15, §16.4) |

---

## 2. Goals, non-goals, and the research claim

### 2.1 Goals
1. A Linux endpoint **agent** that captures network flows (metadata only) and uploads them securely.
2. A cloud-style **backend** that ingests, queues, analyzes (3 layers), stores, and notifies — multi-tenant, authenticated.
3. A **dashboard** to review alerts with evidence, allow/block, and manage settings.
4. An **evidence-grounded explanation layer** (local LLM, constrained) that supports the human decision.
5. A **measured evaluation**: detection quality, system performance, and a small user study (System A vs System B).

### 2.2 Non-goals (say these out loud in the viva — they protect you)
- Not a replacement for commercial EDR; no payload inspection, no endpoint process telemetry.
- Not claiming state-of-the-art detection accuracy. Isolation Forest is a baseline anomaly detector.
- Not a production-ready commercial service (single deployment, demo scale).
- Windows agent, mobile app, billing, SSO: out of scope (Windows service is a stretch).

### 2.3 The research claim (wording to use)
> "We study whether an evidence-grounded LLM explanation, placed between automated detection and a human allow/block decision, improves decision quality and speed compared with presenting the same evidence without explanation."

Hypotheses (write them down **before** running the study, §16.3):
- **H1:** Decision accuracy is higher with explanation (System B) than without (System A).
- **H2:** Decision time is lower with B.
- **H3:** Self-reported confidence is higher with B **and** better calibrated (confidence tracks correctness).
- **H4 (risk probe):** When the explanation is deliberately wrong in a few trials, participants over-rely on it (automation bias). Reported either way.

Be ready for: *"Isn't this just explainable AI (SHAP/LIME)?"* → Those explain a model; here the LLM reconciles **several conflicting detectors** into plain language, and we test whether that actually helps humans, including whether it can mislead them.

---

## 3. Solo scope tiers

| Tier | Meaning | Items |
|------|---------|-------|
| **M — Must** | Project fails without it | Linux agent (sensor + enforcer), authenticated ingestion, Redis Streams, Postgres, 3 detection layers, ONNX model with integrity check, dashboard (alerts, decision, history, settings), email notifications, block/allow loop with safety rules, LLM explainer with fallback, offline + performance + lab evaluation, Docker Compose + TLS, CI with real tests |
| **S — Should** | Strongly improves marks | Telegram notifications (link via code), user study (n ≥ 20), PCA scatter plot, allowlist UI, audit log, keyset pagination, OpenAPI-generated TS types |
| **C — Could** | Only if ahead of schedule | Postgres row-level security, Telegram inline buttons, signed server commands (Ed25519), FFT periodicity (CV-based beacon score is the baseline), supervised baseline model for comparison, Prometheus metrics, Windows service, `.deb` packaging |

**Cut order if behind schedule** (cut from the top first): Windows service → Prometheus → supervised baseline → signed commands → Telegram buttons → RLS → FFT → adversarial-explanation trials. Never cut: tests, tenant isolation, block safety, evaluation.

---

## 4. Timeline (20 weeks, ~15 h/week assumed — adjust if your time differs)

| Phase | Weeks | Deliverable (demoable) | Exit criteria |
|-------|-------|------------------------|---------------|
| 0 Setup & spikes | 1 | Repo, Ubuntu VM lab, dataset downloaded, 4 spikes done | Go/no-go recorded for each spike (§4.1) |
| 1 Contracts & foundations | 2–3 | Shared schemas, DB + migrations, auth, Compose + Caddy TLS, CI green | `docker compose up` works; register/login works; CI runs lint + tests |
| 2 Sensor → ingestion → storage | 4–6 | Agent captures flows → API → Stream → worker → Postgres | Flows visible in DB; kill worker mid-batch → no data lost; duplicates rejected |
| 3 ML & detection | 7–10 | Trained model, ONNX + manifest, 3 layers, evidence objects, alerts | Offline metrics table produced; alerts created from lab traffic |
| 4 Dashboard & notifications | 11–13 | Login, agents, alerts, decision card, history, settings, email (+ Telegram) | End-to-end: attack in lab → alert in UI → email arrives |
| 5 Enforcement | 14–15 | Command channel, enforcer, allowlist, TTL, undo | Block verified with a real connection test; protected IPs refused |
| 6 LLM & study module | 16–17 | Explainer with guard + fallback; study mode in UI | Explanation appears async; fallback works with LLM stopped |
| 7 Evaluation | 18–19 | Perf results, lab results, study data + analysis | All numbers reproducible from scripts |
| 8 Hardening & delivery | 20 | Report, slides, rehearsed demo, README | Fresh-machine install works from README |

Every phase ends with: tests passing in CI, this file updated, and a short note in `docs/PROGRESS.md`.

### 4.1 Phase 0 spikes (do these first — they decide the design)
- **S1 — Model export:** train a tiny `IsolationForest`, convert with `skl2onnx`, load in `onnxruntime`, compare scores to scikit-learn on 100 samples. *Fallback if it fails:* a small autoencoder (PyTorch) exported to ONNX, or One-Class SVM.
- **S2 — Capture rate:** Scapy `AsyncSniffer` + a flow aggregator on your VM; push ~2–5k packets/s with `tcpreplay` or `iperf3`; record CPU and drops. *Fallback:* lower the demo traffic rate, add a BPF filter, or capture with a lighter library for the hot path.
- **S3 — LLM latency:** run the chosen small model in Ollama on your laptop; record time-to-answer for a ~300-token evidence prompt. *Fallback:* smaller model, shorter prompt, or hosted API for the demo (document it).
- **S4 — Compose baseline:** Postgres + Redis + a "hello" FastAPI behind Caddy with TLS. *Fallback:* Nginx with a self-signed cert.

---

## 5. Technology stack and versions

**Rule:** pin to the **current stable** versions at project start, commit lock files, and don't upgrade mid-project unless a bug forces it. (The v1 pins were from 2023 — don't copy them.)

| Area | Choice | Notes |
|------|--------|-------|
| Language | Python 3.11 or 3.12 | Same version in agent, backend, ML env |
| Capture | Scapy (`AsyncSniffer`) | Linux only for MVP. Windows would need Npcap (stretch) |
| API | FastAPI + Uvicorn (Gunicorn optional) | Pydantic **v2** |
| DB | PostgreSQL (current stable, e.g. 16) + SQLAlchemy 2.x async + asyncpg + **Alembic** | Migrations from day one |
| Queue | Redis 7 + `redis-py` (asyncio) | **Streams** |
| ML | scikit-learn, pandas, numpy, `skl2onnx`, `onnxruntime` | Verify sklearn ↔ skl2onnx ↔ onnxruntime compatibility in S1 |
| Auth | `PyJWT`, `argon2-cffi` | No passlib |
| HTTP client | `httpx` (async) | Notifications, Ollama |
| Email | `aiosmtplib` | SMTP creds in env |
| LLM | Ollama (separate container) + `ollama` `AsyncClient` | Small instruct model (3B–8B class); confirm availability in S3 |
| Frontend | React + Vite + TypeScript, Recharts, Axios/fetch, Tailwind | Types generated from OpenAPI |
| Proxy/TLS | Caddy | Automatic HTTPS with a domain; local CA/self-signed for lab |
| Tests | pytest, pytest-asyncio, httpx, (testcontainers or Compose services), Vitest, 1–2 Playwright smoke tests | |
| Quality | ruff, mypy (backend core), `pip-audit`, `npm audit`, gitleaks | In CI |
| Dependency mgmt | `uv` or `pip-tools` | Lock files committed |

**Dev environment:** Ubuntu 22.04/24.04 VM (bridged or host-only network) for the **agent**; Docker on your main machine for the **server**. Create a second VM as the "attacker" for lab tests. (Capturing inside WSL2 will not see your Windows host's traffic.)

**Minimum hardware:** 4 cores, 16 GB RAM recommended if you run the LLM locally alongside everything else (8 GB is tight); 40 GB free disk (dataset + images + models).

### 5.1 Hardware profile and lab setup (Cod's laptop — overrides the generic advice above)

**Machine:** HP Victus 15, Intel i5-12450H (8 cores / 12 threads), **8 GB RAM (7.65 usable)**, NVIDIA RTX 2050 **4 GB VRAM**, ~244 GB free SSD, Windows 11. **Time budget: ~15 h/week.**

**The binding constraint is RAM (8 GB).** Decisions that follow from it:

| Decision | Reason |
|----------|--------|
| Run **Ollama natively on Windows** (uses the GPU), **not** as a Compose service. Backend reaches it at `http://host.docker.internal:11434` (set via `OLLAMA_URL` env var). | Keeps the model in the 4 GB VRAM instead of system RAM; GPU answers in seconds |
| LLM size limit: **3B-class, 4-bit quantized** (verify the exact model in spike S3). Do **not** use 7–8B models. | A 7–8B model won't fit in 4 GB VRAM and would spill into scarce RAM and become slow |
| Docker Desktop with the WSL2 backend, and a `C:\Users\<you>\.wslconfig` file limiting WSL2 memory (start with `memory=3GB`, `processors=6`, `swap=4GB`). | Stops WSL2/Docker from eating all RAM |
| The **monitored endpoint is one Ubuntu Server VM (2 GB RAM, 2 vCPU, 15–20 GB disk, no desktop)**. | Needed for realistic packet capture and iptables tests |
| **No second "attacker" VM.** The Windows host is the attacker (e.g., `nmap` for Windows, Python scripts) over the VM's host-only network. | Saves ~2 GB RAM |
| **Do not run the agent/enforcer inside WSL2.** | WSL2 distros share one network namespace with Docker's engine; our iptables rules and packet capture would mix with Docker's traffic and rules |
| Keep the git repo **inside the WSL2 filesystem** (`~/laptop-shield`), edit with VS Code's WSL extension. | Much faster file I/O than `C:\` mounts |
| Use a small CICIDS2017 subset (Monday benign + 1–2 attack days) first. | Disk and processing time |

**Memory budget (approximate, all running):** Windows + VS Code + browser 3.5–4 GB · WSL2/Docker stack ≤ 3 GB · Ubuntu VM 2 GB · Ollama ~0.5 GB RAM (+ ~2–3 GB VRAM). This is **at the limit** — so don't run everything at once except for the demo, the performance tests and the user study; close browser tabs; stop Ollama when not needed.

**Decision (ADR-001): stay on 8 GB — no RAM upgrade.** All limits above apply as written. (If this ever changes: raise `.wslconfig` memory to ~6 GB and the VM to 3–4 GB.)

**Windows Home (ADR-002):** Hyper-V Manager is not available on Home, so the Ubuntu Server VM will use **VirtualBox** (works alongside WSL2/Docker via the Windows hypervisor platform). Work happens in the **WSL2 Ubuntu terminal**, not Git Bash.

**LLM starting point (ADR-003):** `phi3:mini` is already installed (~2.2 GB, fits in 4 GB VRAM). Use it for spike S3; compare with one other 3B-class model (e.g., `llama3.2:3b` or `qwen2.5:3b`) before choosing the final one.

**Lab network:** the VM gets two adapters — NAT (internet, package installs) and Host-Only (lab; the Windows host reaches the VM here). The server address and the host-only gateway go into the enforcer's **protected set**; lab mode is on only in this VM.

**Spare device option:** any old Linux-capable laptop/PC (or Raspberry Pi) can replace the VM as the monitored endpoint and removes the 2 GB RAM cost.

---

## 6. Shared contracts (the single source of truth)

All schemas live in one installable package, `shield_common`, imported by agent, backend, and ML code. Nothing else may define its own copy of a schema or a feature function.

### 6.1 Telemetry payload (schema v1)

```python
# shield_common/schemas.py
from ipaddress import ip_address
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator

class FlowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flow_id: UUID                      # client-generated; makes retries idempotent
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp", "icmp", "other"]
    start_ts: float = Field(gt=0)      # epoch seconds (UTC)
    duration_s: float = Field(ge=0, le=86_400)

    # features (see §11.1) — all bounded, non-negative
    fwd_packets: int = Field(ge=0)
    bwd_packets: int = Field(ge=0)
    fwd_bytes: int = Field(ge=0)
    bwd_bytes: int = Field(ge=0)
    pkt_len_mean: float = Field(ge=0)
    pkt_len_std: float = Field(ge=0)
    iat_mean_s: float = Field(ge=0)
    syn_count: int = Field(ge=0)
    rst_count: int = Field(ge=0)
    fin_count: int = Field(ge=0)
    uniq_dst_ports_60s: int = Field(ge=0)   # per source host, sliding window
    uniq_dst_ips_60s: int = Field(ge=0)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        return str(ip_address(v))      # raises ValueError for anything invalid; normalizes IPv6

class TelemetryBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    flows: list[FlowRecord] = Field(min_length=1, max_length=500)
```

Notes: no `tenant_id` or `agent_id` in the payload — the server takes them from the authenticated API key. `extra="forbid"` stops silent schema drift. Any change bumps `schema_version`.

### 6.2 Evidence object (what detectors produce, what the LLM and UI consume)

```json
{
  "evidence_version": 1,
  "alert_id": "uuid",
  "flow": { "src_ip": "...", "dst_ip": "...", "dst_port": 443, "protocol": "tcp", "start_ts": 0, "duration_s": 0 },
  "rule": { "hit": true, "list": "blocklist_feed_name", "matched": "dst_ip" },
  "anomaly": { "score": 0.83, "threshold": 0.70, "is_anomalous": true, "model_version": "if-2026-xx-v1" },
  "temporal": { "events_seen": 42, "periodicity_score": 0.91, "baseline_drift": 0.05, "is_periodic": true },
  "key_features": [ { "name": "uniq_dst_ports_60s", "value": 380 } ],
  "conflicts": ["rule_hit_but_anomaly_normal"],
  "severity": "high",
  "severity_policy_version": 1
}
```

Rules for the evidence object: **numbers, booleans, enums, and validated IPs only** — never free text taken from the network (this closes the prompt-injection path). `severity` is computed by deterministic code (§11.6), never by the LLM.

### 6.3 API contract (keyset-paginated, versioned under `/api/v1`)

| Group | Endpoints |
|-------|-----------|
| Auth (user) | `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `GET /me` |
| Agent mgmt (user) | `POST /agents/enrollment-codes`, `GET /agents`, `DELETE /agents/{id}` (revoke) |
| Agent (agent key) | `POST /agent/enroll`, `POST /agent/telemetry`, `GET /agent/commands`, `POST /agent/commands/{id}/ack`, `POST /agent/heartbeat` |
| Alerts (user) | `GET /alerts?status=&cursor=`, `GET /alerts/{id}`, `POST /alerts/{id}/decision` `{action: "allow"\|"block", ttl_minutes}` |
| Flows (user) | `GET /flows?cursor=` (history) |
| Settings (user) | `GET/PUT /settings/notifications`, `POST /settings/telegram/link-code`, allowlist CRUD |
| Study | `/study/*` (separate router, §16.3) |
| Ops | `GET /healthz`, `GET /readyz` |

Generate `openapi.json` in CI and produce the frontend's TypeScript types from it (`openapi-typescript`), so the UI cannot drift from the API.

---

## 7. System architecture (v2)

```
 LINUX ENDPOINT (VM / laptop)                          SERVER HOST (Docker Compose)
┌────────────────────────────────────┐              ┌──────────────────────────────────────────────┐
│ shield-sensor  (CAP_NET_RAW only)  │              │ caddy  :80/:443  (TLS, only exposed service) │
│  Scapy → flows → features → batch  │──HTTPS──────►│   ├─ /api/*  → backend-api                   │
│  disk-buffer (bounded) + retry     │  API key     │   └─ /*      → frontend (static)             │
│                                    │              │                                              │
│ shield-enforcer (CAP_NET_ADMIN)    │◄─HTTPS poll──│ backend-api (FastAPI)                        │
│  polls commands → validates →      │              │   validate → XADD stream:telemetry           │
│  iptables chain SHIELD_BLOCK       │──ack────────►│ backend-worker (same image, other command)  │
└────────────────────────────────────┘              │   XREADGROUP → rules → ONNX → temporal →     │
                                                    │   fuse → bulk insert (Postgres) → XACK        │
                                                    │   → stream:explain / stream:notify           │
                                                    │ postgres (internal network only)             │
                                                    │ redis (internal, password)                   │
                                                    │ ollama (internal, optional profile "llm")    │
                                                    └───────────────┬──────────────────────────────┘
                                                                    ▼
                                                  Email (SMTP) / Telegram (project bot) → user phone
```

**Key principles**
1. **Agent never accepts inbound connections.** It only makes outbound HTTPS calls (telemetry up, commands polled down).
2. **The server never sends shell commands.** It sends a structured command (`block_ip`, `unblock_ip`, IP, TTL); the enforcer re-validates everything locally.
3. **Parsing hostile packets is the riskiest code** → it runs in the sensor with only `CAP_NET_RAW`, as an unprivileged user, with systemd sandboxing. The enforcer never touches packet data.
4. **API and worker are separate processes** so ML work never blocks request handling.
5. **LLM never decides.** It explains; a human decides; the enforcer enforces.

### 7.1 Agent packaging and enrollment
- Package: a Python package installed into a dedicated venv by an installer script (no PyInstaller — avoids antivirus false positives and build complexity).
- **Enrollment flow:** user clicks "Add agent" → server creates a one-time code (valid ~15 min) → on the endpoint: `shield-agent enroll --server https://… --code XXXX` → server returns a long-lived **API key once** → stored at `/etc/shield/agent.conf` (mode `0600`, owned by the service user). The server stores only a hash of the key. Keys can be revoked from the dashboard.
- The agent **refuses `http://`** servers unless started with an explicit `--insecure-dev` flag.
- systemd units: `shield-sensor.service` (`User=shield`, `AmbientCapabilities=CAP_NET_RAW`, `CapabilityBoundingSet=CAP_NET_RAW`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`) and `shield-enforcer.service` (`CAP_NET_ADMIN` only, same hardening). Verify with `systemd-analyze security`.
- Don't distribute the installer as `curl | bash` in the report; ship a tarball + checksum (fine to use a one-liner in the lab).
- Reliability: uploads are batched (≤500 flows), retried with exponential backoff + jitter, and buffered to a **size-capped** local file when offline (oldest dropped first, with a counter reported in heartbeats).

---

## 8. Enforcement design (the "IPS" part) — safe by construction

### 8.1 Flow
1. Detector creates an alert (status `open`).
2. User reviews evidence + explanation → clicks **Block** (with TTL) or **Allow**.
3. Server creates a `block_ip` command (state `pending`).
4. Enforcer polls (every ~10 s), gets the command, **validates**, applies it, then acks (`applied` / `failed` + reason).
5. TTL expiry → enforcer removes the rule and acks `expired`. User can **Undo** anytime (`unblock_ip`).

### 8.2 Safety rules (all enforced in the enforcer, not just the server)
- IP must parse with `ipaddress`; in normal mode it must be **global** (not private, loopback, link-local, multicast, reserved, unspecified).
- Never block: the default gateway, configured DNS resolvers, the Shield server's address, the user's allowlist.
- **Lab mode** (explicit config flag) permits private targets *except* the protected set above — needed because your lab attacker VM is on a private network.
- Every block has a **TTL** (default 60 min, max 24 h). Rules live in a dedicated chain, so cleanup is one command and uninstalling flushes it.
- **Dry-run mode** logs what would happen without changing the firewall (use it for demos on a shared machine).
- Rate-limit the number of active blocks per agent (e.g., 100) to prevent a flood of commands from locking the host out.
- All command results are written to the audit log.

### 8.3 Safe implementation sketch

```python
# agent/enforcer/firewall.py
import ipaddress
import subprocess

CHAIN = "SHIELD_BLOCK"

def validate_target(ip_str: str, protected: set[str], lab_mode: bool) -> ipaddress._BaseAddress:
    ip = ipaddress.ip_address(ip_str)                    # raises ValueError if invalid
    if str(ip) in protected:
        raise ValueError("protected address")
    if not lab_mode and not ip.is_global:
        raise ValueError("non-global address refused")
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise ValueError("special-purpose address refused")
    return ip

def _tool(ip) -> str:
    return "iptables" if ip.version == 4 else "ip6tables"

def ensure_chain() -> None:
    for tool in ("iptables", "ip6tables"):
        # create chain if missing, and jump to it from OUTPUT once
        subprocess.run([tool, "-w", "-N", CHAIN], check=False, capture_output=True)
        if subprocess.run([tool, "-w", "-C", "OUTPUT", "-j", CHAIN], capture_output=True).returncode != 0:
            subprocess.run([tool, "-w", "-I", "OUTPUT", "1", "-j", CHAIN], check=True, capture_output=True)

def block(ip: ipaddress._BaseAddress) -> None:
    tool = _tool(ip)
    rule = ["-d", str(ip), "-j", "DROP"]
    if subprocess.run([tool, "-w", "-C", CHAIN, *rule], capture_output=True).returncode != 0:
        subprocess.run([tool, "-w", "-A", CHAIN, *rule], check=True, capture_output=True, timeout=10)

def unblock(ip: ipaddress._BaseAddress) -> None:
    subprocess.run([_tool(ip), "-w", "-D", CHAIN, "-d", str(ip), "-j", "DROP"], capture_output=True, timeout=10)
```

No `shell=True`, no string building, no `sudo` (privilege comes from the service's capability). Persist active blocks (with expiry) in a small local file so TTLs survive an enforcer restart. Test with a fuzz-style unit test of `validate_target` (invalid strings, private ranges, IPv6 forms, protected set).

---

## 9. Authentication, tenancy, and API security

### 9.1 Users
- Passwords hashed with **Argon2id** (`argon2-cffi`). Minimum length enforced, generic login errors, login rate limiting.
- **Access JWT** short-lived (~15 min) + **refresh token** in an `HttpOnly; Secure; SameSite=Strict` cookie, rotated on use and revocable (store hashed in DB).
- Frontend and API share one origin through Caddy → no CORS needed (and no wildcard CORS ever).

### 9.2 Agents
- API key = 32+ random bytes, shown once, stored as SHA-256 hash (high-entropy secrets don't need slow hashing), compared in constant time.
- Key → `agent_id` → `tenant_id` lookup happens server-side on every request.
- Revoked/expired agents get `401`; an agent with an unexpected `schema_version` gets `422`.

### 9.3 Tenancy rules (non-negotiable)
- Every table that holds user data has `tenant_id NOT NULL`, and every query filters by it through a **single repository layer** (no ad-hoc queries in routes).
- **Mandatory automated test:** create tenants A and B with data; A's token must get `404`/empty for every B resource on every endpoint. This test runs in CI.
- Could-tier hardening: Postgres **row-level security** (`SET LOCAL app.tenant_id`) as a second wall.
- In v2 each user belongs to one tenant (one user ≈ one tenant). Keep the `tenants` table anyway so the model doesn't change later.

### 9.4 Input and abuse controls
- Request body size limit (e.g., 1 MB), batch ≤ 500 flows, per-agent and per-IP rate limits (Redis counters), timeouts everywhere.
- Backpressure: if the telemetry stream length exceeds a high-water mark, return `503` + `Retry-After`; the agent backs off.
- Never return stack traces; log with a request ID. Secrets never appear in logs.

---

## 10. Data pipeline (queue, worker, database)

### 10.1 Redis Streams
- API: validate → `XADD stream:telemetry MAXLEN ~ 100000 * tenant_id … agent_id … payload …` → `202 Accepted`.
- Worker: `XREADGROUP` in a consumer group (`workers`), processes in **batches** (e.g., up to 200), then `XACK` after the DB commit succeeds.
- Crash safety: a periodic `XAUTOCLAIM` re-claims messages idle > 60 s. After N failed attempts (e.g., 5) the message goes to `stream:dead` with the error, and a counter is exposed on `/readyz`/logs.
- Idempotency: `flow_id` has a unique constraint; inserts use `ON CONFLICT DO NOTHING`, so retries never duplicate.
- Redis needs a password, no host-published port, and `appendonly yes` if you want the buffer to survive a Redis restart.

### 10.2 Worker steps (per batch)
1. Load per-tenant allowlist/blocklist caches (refreshed periodically).
2. **Layer 1 – rules** (set lookups).
3. Build the feature matrix with the shared feature module; **batch ONNX inference** (numpy, one call per batch).
4. **Layer 3 – temporal** (per source/destination state in Redis with TTL).
5. **Fuse** into an evidence object and severity (§11.6).
6. One DB transaction: bulk insert flows (+ alerts for those above threshold).
7. `XACK`; enqueue to `stream:notify` and `stream:explain` for new alerts.

### 10.3 Database schema (core tables; all have `tenant_id` except `tenants`)

| Table | Key columns |
|-------|-------------|
| `tenants` | id, name, created_at |
| `users` | id, tenant_id, email (unique), password_hash, created_at |
| `refresh_tokens` | id, user_id, token_hash, expires_at, revoked_at |
| `agents` | id, tenant_id, name, api_key_hash, platform, version, last_seen_at, status, revoked_at |
| `enrollment_codes` | id, tenant_id, code_hash, expires_at, used_at |
| `flows` | flow_id (PK), tenant_id, agent_id, start_ts, src/dst ip+port, protocol, features…, anomaly_score — **range-partitioned by day, retention 7–14 days (drop old partitions)** |
| `alerts` | id, tenant_id, agent_id, flow_id, severity, status (`open/allowed/blocked/dismissed/expired`), evidence JSONB, explanation JSONB, explanation_status, created_at, decided_at, decided_by |
| `commands` | id, tenant_id, agent_id, type, ip, ttl_minutes, state (`pending/applied/failed/expired/reverted`), created_at, acked_at, result |
| `notification_channels` | id, tenant_id, type (`email/telegram`), address_or_chat_id, verified_at |
| `allowlist` | id, tenant_id, cidr_or_ip, note |
| `audit_log` | id, tenant_id, actor, action, target, created_at |
| `study_*` | participants (anonymous code), trials, responses (§16.3) |

Indexes: `(tenant_id, created_at DESC)` on alerts/flows; keyset pagination (`created_at, id`) — never `OFFSET` on big tables. Use **Alembic** for every change; seed data and migrations are tested in CI. Add a nightly `pg_dump` script and a documented restore.

**Retention/privacy:** metadata only (IPs, ports, sizes, timings). No payloads, no URLs, no DNS names. Raw flows auto-expire; alerts and decisions are kept. State this in the report.

---

## 11. Machine learning and detection

### 11.1 Feature set (computed identically live and offline)
Per flow: `duration_s`, `fwd_packets`, `bwd_packets`, `fwd_bytes`, `bwd_bytes`, `pkt_len_mean`, `pkt_len_std`, `iat_mean_s`, `syn_count`, `rst_count`, `fin_count`, `dst_port` (bucketed or log-scaled), `protocol` (one-hot). Per source host over 60 s: `uniq_dst_ports_60s`, `uniq_dst_ips_60s`. Derived in the pipeline: bytes/s, packets/s, byte ratio fwd:bwd.
**Excluded on purpose:** `hour_sin/cos` and any absolute timestamp (leakage), raw IPs (memorization).

The feature function lives only in `shield_common/features.py`. The agent calls it to build the record; the ML scripts call the **same function** to build training data from PCAPs/CSVs. A golden test crafts a tiny PCAP with Scapy and asserts exact feature values.

### 11.2 Data: how to use CICIDS2017 honestly
- **Training data:** benign-only traffic (the Monday capture is benign-only) for the unsupervised model.
- **Evaluation data:** Tuesday–Friday (FTP/SSH brute force, DoS, web attacks, infiltration, botnet, port scan, DDoS).
- **Two paths** (pick per your spike results, document the choice as an ADR):
  - **Path A (recommended baseline):** use the provided flow CSVs, selecting only columns that map to your §11.1 definitions. Fast; some definition mismatch with your live extractor remains → state it as a limitation.
  - **Path B (stronger, heavier):** rebuild flows from the PCAPs with your own extractor (slow in Python; use a subset such as Monday + one attack day). This makes live and offline features truly identical.
- **Always also validate live:** generate your own attacks in an isolated lab (port scan with `nmap`, SYN flood with `hping3`, SSH brute-force against your own VM, a "beacon" script making periodic connections) and show the live pipeline detects them.
- **CSV hygiene:** the CICIDS2017 CSVs contain `Inf`/`NaN`, duplicated header rows and a duplicated column; there is published literature on labeling and extraction issues in this dataset (and corrected versions) — check it, cite it, and mention limitations.
- **Splits:** split by time/file, never random-shuffle individual flows (leakage). Keep a **held-out test set** untouched until the final evaluation.
- Cite the dataset properly (Sharafaldin, Lashkari, Ghorbani, 2018, University of New Brunswick). Respect its license/terms. Use blocklist feeds only if their license allows it, and record the feed name and fetch date.

### 11.3 Training and thresholding
- Pipeline: clean → scale (fit on benign train only) → `IsolationForest` (tune `n_estimators`, `max_samples`, `contamination` as a threshold control only).
- Choose the alert **threshold on a validation set of benign data** (e.g., the score percentile that gives a target false-positive rate), *then* report test results.
- Report: ROC-AUC, PR-AUC, precision/recall/F1 **per attack type**, false-positive rate, and confusion matrices. Expect Isolation Forest to do well on scans/DoS-type volume anomalies and poorly on low-and-slow or application-layer attacks — say so; it supports why multiple layers exist.
- Reproducibility: fixed seeds, `ml/` scripts (`prepare_data.py → train.py → export_onnx.py → evaluate.py`), config in YAML, results written to `ml/results/`.

### 11.4 Model integrity and loading

```
ml/models/
  model.onnx
  manifest.json   # model_version, sha256(model.onnx), feature_names (ordered), scaler params,
                  # threshold, score_semantics, training data description, metrics, schema_version
```

```python
# backend/app/detection/anomaly.py
import hashlib, json, os
import numpy as np
import onnxruntime as ort

class ModelIntegrityError(RuntimeError): ...

def load_model(model_path: str, manifest_path: str):
    manifest_bytes = open(manifest_path, "rb").read()
    if hashlib.sha256(manifest_bytes).hexdigest() != os.environ["SHIELD_MODEL_MANIFEST_SHA256"]:
        raise ModelIntegrityError("manifest hash mismatch")
    manifest = json.loads(manifest_bytes)

    model_bytes = open(model_path, "rb").read()            # read once
    if hashlib.sha256(model_bytes).hexdigest() != manifest["model_sha256"]:
        raise ModelIntegrityError("model hash mismatch")
    session = ort.InferenceSession(model_bytes, providers=["CPUExecutionProvider"])  # load the same bytes
    return session, manifest
```

- Expected manifest hash comes from an environment variable/secret (set at deploy time), not from the same folder as the model — otherwise an attacker who replaces the model replaces the hash too. Be accurate in the report: this is **integrity checking**, not full cryptographic signing (signing with a key is a Could-tier upgrade).
- After S1, **inspect `session.get_outputs()`** and select the score output **by name**; write a unit test that compares ONNX scores to scikit-learn on fixed samples; convert to one documented convention (e.g., `anomaly_score ∈ [0,1]`, higher = more anomalous) and store it in the manifest.
- The server refuses to start (or marks `/readyz` failed) if the feature order/length in the manifest doesn't match `shield_common`.

### 11.5 Detection layers

| Layer | Method | Output |
|-------|--------|--------|
| 1 Rules | In-memory `set` for blocklist IPs/CIDRs (refreshed from a public feed + manual list); simple heuristics (e.g., `uniq_dst_ports_60s` above a bound ⇒ scan) | `rule.hit`, which list/heuristic |
| 2 Anomaly | ONNX Isolation Forest on the §11.1 vector | score, threshold, is_anomalous |
| 3 Temporal | Per (source, destination, port) keep the last ~64 flow start times in Redis (TTL). **Baseline:** coefficient of variation of inter-arrival times → periodicity score (low CV with ≥ 20 events ⇒ beacon-like). **Could-tier:** bin to a regular series and use FFT/autocorrelation peak strength. Drift guard below. | events_seen, periodicity_score, baseline_drift, is_periodic |

**Drift guard (what "poisoning filter" should really mean):** the Isolation Forest is **frozen** — nothing learns from live traffic, so the model can't be poisoned at runtime. Only the temporal layer keeps per-destination baselines (EWMA); to stop "slow drift" attacks, cap how fast a baseline may move and compare it against a frozen reference snapshot; large divergence raises `baseline_drift` and flags the path. Describe it exactly like this in the report — don't claim online learning.

### 11.6 Fusion and severity (deterministic, versioned)

| Condition | Severity |
|-----------|----------|
| rule hit **and** anomalous | critical |
| rule hit only | high |
| anomalous **and** periodic | high |
| anomalous only, score ≥ high threshold | medium |
| periodic only, or anomalous slightly above threshold | low |
| none | no alert |

`conflicts[]` records disagreements (e.g., `rule_hit_but_anomaly_normal`, `anomalous_but_no_rule`). Policy version is stored with each alert so results stay reproducible. **Alert hygiene:** dedupe per (tenant, src, dst, type) in a time window and cap notifications per hour, so a scan can't create thousands of alerts or messages.

### 11.7 2-D plot
Fit PCA offline on the training features, store its components in the manifest, and have the worker compute `(x, y)` per alerted flow. The dashboard plots normal-sample background vs alerts. Label it "PCA projection", not "clusters".

---

## 12. Notifications and dashboard

### 12.1 Notifications
- **Email:** project SMTP account via env vars; users only enter their address; verify it with a link.
- **Telegram:** one project bot. User clicks "Link Telegram" → gets a one-time code → sends `/start <code>` to the bot → server stores the `chat_id`. Messages contain severity, a short summary and a **link to the alert in the dashboard** (decision happens after login).
- Telegram `getUpdates` long-polling avoids needing a public webhook. Correct API base is `https://api.telegram.org/bot<TOKEN>/…`.
- Optional (Could): inline buttons with **signed, expiring, single-use** callback tokens that map to an alert + tenant; callbacks are verified against the linked `chat_id`. Remember Telegram's 64-byte `callback_data` limit — put only a short token there.
- Notifications run from `stream:notify` with retries and a per-tenant rate limit; failures are logged, never block the pipeline.

### 12.2 Frontend pages
Login/Register · Agents (enroll, status, revoke) · Alerts list (filters, keyset paging) · **Decision card** (evidence table, conflict badges, explanation panel, Allow / Block + TTL, Undo) · History · Settings (email, Telegram link, allowlist) · Detection plot · Study mode (later).
- Access token kept in memory; refresh via cookie; poll alerts every ~5 s (SSE is optional later).
- Show the explanation panel states: `pending`, `ready`, `fallback`. The alert is usable **before** the LLM finishes.
- Escape/encode all displayed data (IPs and numbers only, but treat everything as untrusted); set a strict `Content-Security-Policy` in Caddy.

---

## 13. Deployment (Docker Compose)

Principles: one command to start, nothing sensitive in git, minimum exposed ports.

```yaml
# deploy/docker-compose.yml  (outline — fill in during Phase 1)
services:
  caddy:       { image: caddy:2, ports: ["80:80", "443:443"], volumes: [Caddyfile, caddy_data], depends_on: [backend-api, frontend] }
  frontend:    { build: ../frontend }                      # static files served via Caddy or an internal Nginx
  backend-api: { build: ../backend, command: gunicorn -k uvicorn.workers.UvicornWorker app.main:app -b 0.0.0.0:8000,
                 env_file: .env, depends_on: { postgres: {condition: service_healthy}, redis: {condition: service_healthy} } }
  backend-worker: { build: ../backend, command: python -m app.workers.pipeline, env_file: .env }
  postgres:    { image: postgres:16, env_file: .env, volumes: [pg_data], healthcheck: {...} }   # no published ports
  redis:       { image: redis:7, command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes, healthcheck: {...} }
  ollama:      { image: ollama/ollama, profiles: ["llm"], volumes: [ollama_models] }
```

- `.env.example` is committed; real `.env` is git-ignored; CI runs **gitleaks**.
- `docker-compose.dev.yml` adds `--reload`, published DB ports on `127.0.0.1` only, and mail catcher.
- Run containers as non-root, pin base-image versions, multi-stage builds, `.dockerignore`, resource limits for the worker and Ollama.
- Don't use the obsolete top-level `version:` key.
- Health endpoints: `/healthz` (process alive), `/readyz` (DB, Redis, model loaded, stream lag, dead-letter count).
- Logs: structured JSON, request ID, tenant/agent IDs (no secrets). Optional Prometheus `/metrics` (Could).
- Demo/cloud: a small VPS with a domain (automatic HTTPS) **or** laptop + Caddy local CA. Have the **offline demo fallback** ready (§15).

---

## 14. LLM explanation layer

### 14.1 Behavior
- Triggered **after** the alert is stored, via `stream:explain`; the UI shows the alert immediately and fills the explanation in when ready.
- Ollama runs as its own container; model is a small instruct model chosen after spike S3. Use `AsyncClient`, **temperature 0**, a hard timeout (~30 s), and one retry.
- Request **structured JSON** output (Ollama supports a JSON schema via its `format` option in recent versions — confirm in S3). Fields: `why_flagged`, `signal_conflicts`, `risk_level`, `recommended_action` (enum: `allow`, `block`, `investigate`), `confidence_note`.
- Cache by hash of the evidence object.

### 14.2 Guard (the anti-hallucination part)
After generation, run checks: every IP/number in the text must appear in the evidence object; `risk_level` must not be *lower* than the deterministic severity by more than one step (or simply is shown beside it); no URLs, no filenames, no commands; length limits. If any check fails or the call times out → **deterministic template explanation** built from the evidence (status `fallback`). Store `explanation_status` and the model name/version.

### 14.3 Prompt (starting point — iterate with evaluation)
```
System: You are a network-security triage assistant. Use ONLY the fields in the JSON evidence.
Do not add facts, IPs, ports, tools or attack names that are not in the JSON. If signals conflict,
say which detectors disagree and what that could mean in general terms. Output JSON matching the schema.
User: <evidence JSON>
```
- The evidence contains no free text from the network, so network data cannot inject instructions.
- The LLM output is **advice displayed to a human**; no code path lets it create a command.
- Privacy argument for the report: the model runs locally, so evidence never leaves the deployment.

---

## 15. Risk register (known risks, mitigations, fallbacks)

| # | Risk | Likelihood / impact | Mitigation | Fallback |
|---|------|--------------------|------------|----------|
| 1 | Isolation Forest → ONNX conversion or version mismatch | Med / High | Spike S1 in week 1; pinned versions | Autoencoder→ONNX or One-Class SVM |
| 2 | Scapy can't keep up with traffic | Med / Med | BPF filter, batching, benchmark in S2 | Lower demo rate; document limit |
| 3 | Offline features differ from live features | High / High | Shared feature module + golden tests + lab validation | State as limitation; Path B subset |
| 4 | Low detection accuracy on some attacks | High / Med | Report per-attack honestly; multi-layer story | Add optional supervised baseline |
| 5 | LLM too slow / wrong / unavailable | Med / Med | Async job, guard, fallback template, small model | Hosted API for demo (disclosed) |
| 6 | Alert storm (scan → thousands of alerts/messages) | High / Med | Dedupe windows, rate limits, severity policy | Disable notifications for low severity |
| 7 | False-positive block cuts the user off | Med / High | Protected set, TTL, undo, dry-run, lab mode | Console flush command: `shield-enforcer flush` |
| 8 | Tenant data leak | Low / Critical | Repository layer, mandatory isolation test, optional RLS | Block release until test passes |
| 9 | Solo schedule slips | High / High | Tiers, cut order, buffer weeks, weekly review | Cut per §3 |
| 10 | Study participants too few / low power | Med / Med | Recruit early, n ≥ 20, within-subjects design | Present as exploratory pilot with effect sizes + CIs |
| 11 | Demo-day failure (network, TLS, LLM, VM) | Med / High | Scripted demo, offline compose, recorded backup video, LLM fallback | Run everything on one laptop, local CA |
| 12 | Ethics/consent problem | Low / High | Written consent, anonymous IDs, institutional approval, isolated lab only | Drop study; use expert walkthrough |
| 13 | Dependency vulnerabilities / drift | Med / Med | Lock files, `pip-audit`, `npm audit`, no mid-project upgrades | Pin and patch only critical issues |
| 14 | Agent stuck/crashed unnoticed | Med / Low | Heartbeats, "last seen" in UI, systemd `Restart=on-failure` | — |
| 15 | Data loss (DB/Redis) | Low / Med | Nightly `pg_dump`, Redis AOF, documented restore | Re-run lab data generation |

---

## 16. Testing, CI, and evaluation

### 16.1 Test suite (claim only what exists)
- **Unit:** feature extractor (golden PCAP), IP/target validation (fuzz), severity policy table, schema validation edge cases, model loader (good hash / bad hash), ONNX vs sklearn parity.
- **Integration:** auth flows, agent enrollment, telemetry → stream → worker → DB, retry/dead-letter, tenant isolation (A vs B on every endpoint), command lifecycle, notification failure doesn't break pipeline.
- **System/lab:** scripted scenarios on VMs (port scan, SYN flood, brute force, beacon) with expected alerts.
- **Frontend:** Vitest for components, 1–2 Playwright smoke tests (login → alert → decision).
- **CI (GitHub Actions):** ruff, mypy (core), pytest with Postgres/Redis services, frontend build + tests, `pip-audit`, `npm audit`, gitleaks, Docker build. Keep the badge honest; report the real test count in the final report.

### 16.2 Performance evaluation
Load generator (custom script or Locust) posts synthetic batches: measure **ingest throughput, p50/p95/p99 API latency, end-to-end latency (flow → alert), worker lag, drop/retry counts, CPU/RAM of agent and worker**. Include a spike test showing backpressure working (503 + retries, no loss). Present as tables and graphs with the hardware stated.

### 16.3 User study (System A vs System B)
- **Design:** within-subjects, counterbalanced. Each participant handles two sets of ~10 alerts: one set under **A** (evidence only), one under **B** (evidence + explanation). Set assignment and order are randomized across participants.
- **Stimuli:** pre-selected held-out alerts (about half malicious, half benign), including several with **conflicting detector signals**. Ground truth from dataset labels. (H4: include 2 trials where the explanation is deliberately wrong, flagged in the data, pre-declared in the consent info as "some explanations may be inaccurate".)
- **Participants:** ≥ 20 CS students (state that most are not professional analysts — a limitation); consider a few with security background for a sub-analysis.
- **Measures:** correctness vs ground truth, decision time (client-side timestamps), confidence (1–5), a short post-task questionnaire (clarity, trust; optionally SUS-style items).
- **Analysis:** paired **Wilcoxon signed-rank** for time/confidence, **McNemar** or paired comparison for accuracy; report effect sizes and 95% CIs, not only p-values; calibration (confidence vs correctness); report H4 separately. With ~20–30 participants only large effects are detectable — state it.
- **Write down hypotheses and analysis plan before collecting data.**
- **Ethics:** get written approval from your guide/department; informed consent; anonymous participant codes; no personal data stored; data deletion on request; study data kept in separate tables from tenant data.
- Build a minimal **study mode** (`/study/*` + a UI page) that randomizes, times, and records responses.

### 16.4 Responsible-use rules
- Run attack tools **only** in your isolated lab network against your own VMs. Never scan or attack others.
- Monitor only machines you own or have written permission to monitor; the agent collects metadata only and the report should say so.
- Keep third-party data (CICIDS2017, blocklists) within license terms and cite them.

---

## 17. Repository layout and working rules

```
laptop-shield/
├── README.md                    # install + run + demo in < 10 steps
├── docs/
│   ├── MASTER_PLAN.md           # this file
│   ├── PROGRESS.md              # dated log, one entry per session
│   ├── adr/                     # one short file per decision (ADR-001-…)
│   ├── threat-model.md
│   └── study/                   # protocol, consent form, analysis notebook
├── shared/shield_common/        # schemas.py, features.py, ipcheck.py  (installable package)
├── agent/
│   ├── sensor/  enforcer/  installer/  tests/
├── backend/
│   ├── app/{api,core,db,services,workers,detection,notify,explain}/
│   ├── alembic/  tests/  Dockerfile
├── ml/
│   ├── configs/  scripts/  notebooks/  models/  results/   # data/ is git-ignored
├── frontend/                    # Vite + React + TS
├── deploy/                      # docker-compose.yml, compose.dev.yml, caddy/, .env.example
├── scripts/                     # lab traffic generators, load test, backup/restore
└── .github/workflows/ci.yml
```

### Working rules
1. **Contracts first.** Change `shield_common` (and bump versions) before changing any consumer.
2. **One vertical slice at a time**, always demoable.
3. **Every decision gets an ADR** (3–6 lines: context, decision, consequences). Update this plan when it changes.
4. **Definition of done** for any task: code + tests + docs line + CI green.
5. **No secrets in git. No `shell=True`. No raw SQL without bound parameters. No queries outside the repository layer.**
6. **Weekly review (30 min):** compare against §4, update §0 status, move items between tiers if needed.

### How we work together (session protocol)
- Start each session by telling me the **current phase and last completed task** (paste the latest `PROGRESS.md` entry), and share the relevant files or error output — I can't see your repo or machine unless you paste or upload content.
- I will check proposals against this plan, flag deviations or new risks, write/review code for the current task, and suggest the matching tests.
- End each session with: what was done, what's next, any new decision (→ ADR) or risk (→ §15).

---

## 18. Deliverables checklist

- [ ] Working system demo (scripted scenario: scan from attacker VM → alert → explanation → block → verify → undo)
- [ ] Source repo with README, CI badge (honest), license
- [ ] ML evaluation report (tables per attack type, limitations)
- [ ] Performance report
- [ ] User-study report (protocol, data, statistics, limitations)
- [ ] Threat model and security design summary
- [ ] Final project report (suggested chapters: Introduction · Related work (IDS/EDR, XAI for security, LLMs in SOC) · Requirements · Architecture · Implementation · Evaluation · Limitations & ethics · Conclusion)
- [ ] Slides + 5-minute backup demo video + offline demo environment

---

## 19. Demo script (rehearse until boring)

1. Show the dashboard with a registered agent (green, "last seen: seconds ago").
2. From the attacker VM run an `nmap` scan against the monitored VM (lab network).
3. Alert appears (severity, evidence, conflict badge); notification arrives on phone/email.
4. Explanation panel fills in (or shows fallback label if the LLM is stopped — demonstrate this deliberately).
5. Click **Block (15 min)** → enforcer applies → show a failed connection from the monitored VM to the blocked address → click **Undo** → connection works again.
6. Show the evaluation graphs and the A/B study results; close with limitations and future work.

---

*Version 2.0 — created from the v1 review. Keep this document current; it is the project's memory.*
