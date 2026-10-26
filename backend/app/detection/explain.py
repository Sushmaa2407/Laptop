"""Plain-English explanations of alerts.

The local LLM (Ollama) writes the explanation, but the system never depends on it:
- the prompt contains only validated numbers, enums and IP addresses from the Evidence record (no free text from the network)
- the answer must parse as JSON and pass the ExplanationOut checks, otherwise we use the deterministic template
- the recommended action is only advice; the person always decides (and is clamped to the severity, see clamp_action)
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Action = Literal["block", "allow", "monitor"]
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

SYSTEM_PROMPT = (
    "You are a security assistant inside a laptop protection tool. You receive one alert as JSON. Explain it in plain "
    "English for a student who is not a security expert.\n"
    "Rules:\n"
    "- Use ONLY the sentences in 'facts' and the fields given. Never add numbers, addresses, tools, attackers or intentions.\n"
    "- Never comment on port numbers or say a port is common, rare or unusual.\n"
    "- 'summary' must be exactly 3 short sentences: (1) what happened, (2) why that is suspicious, (3) how sure we are, "
    "based on 'severity' and 'conflicts'.\n"
    "- 'reasons' is 2 or 3 short strings, each a rewording of one item in 'facts'.\n"
    "- If 'conflicts' is not empty, say the evidence is mixed and recommend 'monitor'.\n"
    "- 'recommended_action' is exactly one of: block, allow, monitor. The human makes the final decision.\n"
    "Reply with JSON only."
)

JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "recommended_action": {"type": "string", "enum": ["block", "allow", "monitor"]},
    },
    "required": ["summary", "reasons", "recommended_action"],
}


class ExplanationOut(BaseModel):
    model_config = ConfigDict(extra="ignore")

    summary: Annotated[str, StringConstraints(strip_whitespace=True, min_length=20, max_length=700)]
    reasons: Annotated[list[Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=240)]],
                       Field(min_length=1, max_length=5)]
    recommended_action: Action


def facts_for(evidence: dict) -> list[str]:
    """Plain-English facts taken straight from the evidence. The LLM may only reword these."""
    flow, rule, anomaly = evidence["flow"], evidence["rule"], evidence["anomaly"]
    feats = {f["name"]: f["value"] for f in evidence["key_features"]}
    src, dst = flow["src_ip"], flow["dst_ip"]
    out = []
    category = rule["list_name"] if rule["hit"] else None
    if category == "port_scan":
        out.append(f"{src} touched {int(feats.get('uniq_dst_ports_60s', 0))} different ports on {dst} within 60 seconds")
    elif category == "host_sweep":
        out.append(f"{src} contacted {int(feats.get('uniq_dst_ips_60s', 0))} different machines within 60 seconds")
    elif category == "syn_flood":
        out.append(f"{src} sent a burst of connection-start (SYN) packets to {dst} and the connections were never completed")
    elif category == "beaconing":
        out.append(f"{src} contacted {dst} {int(feats.get('beacon_events', 0))} times at regular intervals of about {feats.get('beacon_period_s', 0):g} seconds")
        out.append(f"The timing regularity score is {evidence['temporal']['periodicity_score']:.2f} out of 1")
    elif category == "brute_force":
        out.append(f"{src} made {int(feats.get('repeat_connections_60s', 0))} separate login connections to {dst} within 60 seconds")
    else:
        out.append("No fixed rule matched this traffic")
    out.append(f"The anomaly model scored this traffic {anomaly['score']:.2f} out of 1; the alert line is {anomaly['threshold']:.2f}")
    if anomaly["is_anomalous"]:
        out.append("The anomaly model considers this traffic unusual compared with normal activity")
    else:
        out.append("The anomaly model considers this traffic normal")
    return out


def prompt_payload(evidence: dict) -> dict:
    """The part of the evidence the LLM gets to see: words and a few numbers, no raw ports or packet fields."""
    flow = evidence["flow"]
    return {
        "severity": evidence["severity"],
        "source_ip": flow["src_ip"],
        "target_ip": flow["dst_ip"],
        "facts": facts_for(evidence),
        "conflicts": evidence["conflicts"],
    }


def build_messages(evidence: dict) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(prompt_payload(evidence), separators=(",", ":"))},
    ]


def clamp_action(action: str, severity: str) -> str:
    """Advice must not contradict the severity: never 'allow' a high/critical alert, never 'block' a low one."""
    if severity in ("high", "critical") and action == "allow":
        return "monitor"
    if severity == "low" and action == "block":
        return "monitor"
    return action


_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUM = re.compile(r"\d+(?:\.\d+)?")


def _check_grounded(text: str, evidence: dict) -> None:
    """Reject answers that mention numbers or addresses that are not in the evidence."""
    flow, anomaly = evidence["flow"], evidence["anomaly"]
    for ip in _IP.findall(text):
        if ip not in (flow["src_ip"], flow["dst_ip"]):
            raise ValueError(f"mentions an address that is not in the evidence: {ip}")
    allowed = {60.0, 1.0, round(anomaly["score"], 2), round(anomaly["threshold"], 2),
               float(round(anomaly["score"] * 100)), float(round(anomaly["threshold"] * 100))}
    for fact in facts_for(evidence):
        for n in _NUM.findall(_IP.sub("", fact)):
            allowed.add(float(n))
    for n in _NUM.findall(_IP.sub("", text)):
        if float(n) not in allowed:
            raise ValueError(f"mentions a number that is not in the evidence: {n}")


def parse_llm_answer(raw: str, severity: str, evidence: dict | None = None) -> dict:
    """Validate the model's reply. Raises ValueError if it is unusable."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("not valid JSON") from exc
    try:
        out = ExplanationOut.model_validate(data)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"does not match schema: {exc}") from exc
    sentences = [x for x in re.split(r"(?<=[.!?])\s+", out.summary.strip()) if x]
    if not 2 <= len(sentences) <= 5:
        raise ValueError(f"summary has {len(sentences)} sentences, expected about 3")
    if evidence is not None:
        _check_grounded(" ".join([out.summary, *out.reasons]), evidence)
    clean = out.model_dump()
    clean["summary"] = _CTRL.sub("", clean["summary"])
    clean["reasons"] = [_CTRL.sub("", r) for r in clean["reasons"]]
    clean["recommended_action"] = clamp_action(clean["recommended_action"], severity)
    return clean


# ------------------------------------------------------------------ deterministic fallback
def template_explanation(evidence: dict) -> dict:
    flow, rule, anomaly = evidence["flow"], evidence["rule"], evidence["anomaly"]
    feats = {f["name"]: f["value"] for f in evidence["key_features"]}
    src, dst = flow["src_ip"], flow["dst_ip"]
    category = rule["list_name"] if rule["hit"] else None
    ports, hosts = int(feats.get("uniq_dst_ports_60s", 0)), int(feats.get("uniq_dst_ips_60s", 0))
    score = anomaly["score"]

    if category == "port_scan":
        what = f"{src} contacted {ports} different ports on this machine within one minute."
        why = "Probing many ports quickly is how attackers look for open services (a port scan)."
        reasons = [f"{ports} distinct destination ports in 60 seconds"]
    elif category == "host_sweep":
        what = f"{src} contacted {hosts} different hosts within one minute."
        why = "Touching many machines in a row is typical of a network sweep that maps out targets."
        reasons = [f"{hosts} distinct destination hosts in 60 seconds"]
    elif category == "beaconing":
        n, period = int(feats.get("beacon_events", 0)), feats.get("beacon_period_s", 0)
        what = f"{src} contacted {dst} {n} times at regular intervals of about {period:g} seconds."
        why = ("Software that checks in with a remote address on a fixed schedule can be malware waiting for orders; "
               "legitimate update checks and monitoring tools behave the same way.")
        reasons = [f"{n} contacts, about every {period:g} seconds", f"Timing regularity {evidence['temporal']['periodicity_score']:.2f} out of 1"]
    elif category == "brute_force":
        n = int(feats.get("repeat_connections_60s", 0))
        what = f"{src} made {n} separate login connections to {dst} within one minute."
        why = "Many quick, repeated logins to the same service are typical of password guessing (a brute-force attack)."
        reasons = [f"{n} login connections in 60 seconds"]
    elif category == "syn_flood":
        what = f"{src} opened a large number of connections to {dst} that were never completed."
        why = "A burst of half-open connections is the signature of a SYN flood, which tries to exhaust a server."
        reasons = [f"{int(feats.get('syn_count', 0))} SYN packet(s) in this flow and none answered"]
    else:
        what = f"The traffic from {src} looks unusual compared with normal activity on this machine."
        why = "The anomaly model scored it far from the traffic it learned as normal, but no fixed rule matched."
        reasons = ["No fixed rule matched, so this rests on the anomaly score alone"]
    reasons.append(f"Anomaly score {score:.2f} (alert threshold {anomaly['threshold']:.2f})")
    if evidence["conflicts"]:
        reasons.append("The rule check and the anomaly model disagree, so the evidence is mixed")

    sure = {"critical": "We are quite sure this is hostile.", "high": "We are fairly sure this is suspicious.",
            "medium": "We are only moderately sure.", "low": "We are not very sure; this may be harmless."}[evidence["severity"]]
    action = {"critical": "block", "high": "block"}.get(evidence["severity"], "monitor")
    if evidence["conflicts"]:
        action = "monitor"
    return {"summary": f"{what} {why} {sure}", "reasons": reasons[:5], "recommended_action": action}


# ------------------------------------------------------------------ Ollama client (blocking; run in a thread)
class LlmError(Exception):
    pass


def ollama_chat(base_url: str, model: str, messages: list[dict], timeout: float = 90.0) -> str:
    body = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "format": JSON_SCHEMA,
        "keep_alive": "30m",  # first load takes ~1 minute; keep the model in memory afterwards
        "options": {"temperature": 0.2, "num_ctx": 2048, "num_predict": 320},
    }).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/api/chat", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL comes from our own config
            data = json.loads(resp.read())
        return data["message"]["content"]
    except (urllib.error.URLError, TimeoutError, OSError, KeyError, json.JSONDecodeError) as exc:
        raise LlmError(str(exc)) from exc


def warm_up(base_url: str, model: str) -> None:
    """Load the model into memory so the first real alert is not slow."""
    body = json.dumps({"model": model, "keep_alive": "30m"}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/api/generate", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=180).read()  # noqa: S310
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LlmError(str(exc)) from exc
