import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const NOW = new Date().toISOString();
const evidence = {
  flow: { src_ip: "192.168.56.1", dst_ip: "192.168.56.103", src_port: 40000, dst_port: 22, protocol: "tcp", start_ts: 1.8e9, duration_s: 0.01 },
  rule: { hit: true, list_name: "port_scan", matched: "heuristic" },
  anomaly: { score: 0.67, threshold: 0.5, is_anomalous: true, model_version: "iforest-v1" },
  key_features: [
    { name: "uniq_dst_ports_60s", value: 150 },
    { name: "syn_count", value: 1 },
    { name: "pkt_len_mean", value: 44.0 },
  ],
  conflicts: [],
  severity: "high",
};
let alert;
let calls;

function respond(body, status = 200) {
  return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
}

beforeEach(() => {
  sessionStorage.setItem("shield_token", "t");
  calls = [];
  alert = {
    id: "a1", agent_id: "g1", flow_id: null, severity: "high", status: "open", evidence,
    explanation: { summary: "A host probed many ports. That is typical of a scan. We are fairly sure.", reasons: ["150 ports in 60 seconds"],
      recommended_action: "block", source: "llm", model: "llama3.2:3b" },
    explanation_status: "ready", created_at: NOW, decided_at: null,
  };
  globalThis.fetch = vi.fn((url, opts = {}) => {
    calls.push([opts.method || "GET", url, opts.body]);
    if (url.startsWith("/api/v1/stats")) return respond({ open_alerts: 1, alerts_24h: 3, flows_5m: 412, agents_online: 1 });
    if (url.startsWith("/api/v1/agents")) return respond([{ id: "g1", name: "vm-sensor", status: "active", last_seen_at: NOW, created_at: NOW }]);
    if (url === "/api/v1/alerts/a1/commands")
      return respond(alert.status === "blocked" ? [{ id: "c1", type: "block_ip", ip: "192.168.56.1", ttl_minutes: 60, state: "applied", result: "ok", created_at: NOW, acked_at: NOW }] : []);
    if (url === "/api/v1/alerts/a1/decision") {
      alert = { ...alert, status: "blocked" };
      return respond(alert);
    }
    if (url === "/api/v1/alerts/a1") return respond(alert);
    if (url.startsWith("/api/v1/alerts")) return respond(alert.status === "open" ? [alert] : []);
    return respond({}, 404);
  });
});
afterEach(cleanup);

describe("dashboard", () => {
  it("shows the alert in plain words and blocks after a confirm click", async () => {
    const { default: App } = await import("./App.jsx");
    render(<App />);
    expect(await screen.findByText(/probed 150 ports on 192.168.56.103/)).toBeTruthy();
    expect(screen.getByText(/That is typical of a scan/)).toBeTruthy();
    expect(screen.getByText(/Written by llama3.2:3b/)).toBeTruthy();
    expect(screen.getByText("vm-sensor")).toBeTruthy();

    const block = screen.getByRole("button", { name: "Block 192.168.56.1" });
    fireEvent.click(block);
    expect(calls.some((c) => c[1].endsWith("/decision"))).toBe(false); // first click only arms it
    fireEvent.click(screen.getByRole("button", { name: /Confirm: block 192.168.56.1/ }));

    await waitFor(() => expect(calls.some((c) => c[1].endsWith("/decision"))).toBe(true));
    const sent = JSON.parse(calls.find((c) => c[1].endsWith("/decision"))[2]);
    expect(sent).toEqual({ action: "block", ttl_minutes: 60 });
    expect(await screen.findByText(/Block 192.168.56.1 for 60 min/)).toBeTruthy();
    expect(await screen.findByText(/Done on the machine/)).toBeTruthy();
  });

  it("explains a beaconing alert and blocks the remote address, not the protected machine", async () => {
    alert = {
      ...alert,
      evidence: {
        ...evidence,
        flow: { ...evidence.flow, src_ip: "192.168.56.103", dst_ip: "192.168.56.104", dst_port: 8080 },
        rule: { hit: true, list_name: "beaconing", matched: "heuristic" },
        temporal: { events_seen: 12, periodicity_score: 0.93, baseline_drift: 0, is_periodic: true },
        key_features: [{ name: "beacon_period_s", value: 10 }, { name: "beacon_events", value: 12 }],
        severity: "medium",
      },
      severity: "medium",
    };
    const { default: App } = await import("./App.jsx");
    render(<App />);
    expect(await screen.findByText(/contacts 192.168.56.104 about every 10 seconds/)).toBeTruthy();
    expect(screen.getByText(/Regular rhythm/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Block 192.168.56.104" })).toBeTruthy();
  });

  it("falls back to the login screen without a token", async () => {
    sessionStorage.clear();
    vi.resetModules();
    const { default: App } = await import("./App.jsx");
    render(<App />);
    expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
  });
});
