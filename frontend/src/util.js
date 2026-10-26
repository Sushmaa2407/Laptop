// Everything that turns raw evidence into words a person can read.

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const FEATURE_LABELS = {
  uniq_dst_ports_60s: "Different ports touched in 60 s",
  uniq_dst_ips_60s: "Different machines touched in 60 s",
  syn_count: "Connection-start packets (SYN)",
  rst_count: "Connection resets (RST)",
  fin_count: "Connection closes (FIN)",
  fwd_packets: "Packets sent by the source",
  bwd_packets: "Packets sent back",
  pkt_len_mean: "Average packet size (bytes)",
  duration_s: "Flow duration (s)",
  iat_mean_s: "Average gap between packets (s)",
  repeat_connections_60s: "Login connections to the same service in 60 s",
  half_open_10s: "Unfinished connection attempts in 10 s",
  beacon_period_s: "Check-in interval (s)",
  beacon_events: "Check-ins seen",
};

const CONFLICT_TEXT = {
  rule_hit_but_anomaly_normal: "A fixed rule matched, but the learning model finds this traffic normal. The evidence is mixed.",
  anomalous_but_no_rule: "The learning model finds this unusual, but no fixed rule matched. Treat it with care.",
};

export const featureLabel = (name) => FEATURE_LABELS[name] || name;
export const conflictText = (c) => CONFLICT_TEXT[c] || c;

export function features(alert) {
  const map = {};
  for (const f of alert.evidence.key_features || []) map[f.name] = f.value;
  return map;
}

export function kindOf(alert) {
  const rule = alert.evidence.rule;
  return rule?.hit ? rule.list_name : "anomaly";
}

export const KIND_LABEL = {
  port_scan: "Port scan",
  host_sweep: "Host sweep",
  syn_flood: "SYN flood",
  brute_force: "Password guessing",
  beaconing: "Regular check-ins",
  anomaly: "Unusual traffic",
};

export function headline(alert) {
  const { flow } = alert.evidence;
  const f = features(alert);
  switch (kindOf(alert)) {
    case "port_scan":
      return `${flow.src_ip} probed ${Math.round(f.uniq_dst_ports_60s)} ports on ${flow.dst_ip}`;
    case "host_sweep":
      return `${flow.src_ip} contacted ${Math.round(f.uniq_dst_ips_60s)} machines within a minute`;
    case "syn_flood":
      return `${flow.src_ip} opened connections to ${flow.dst_ip} that were never completed`;
    case "beaconing":
      return `${flow.src_ip} contacts ${flow.dst_ip} about every ${Math.round(f.beacon_period_s)} seconds`;
    case "brute_force":
      return `${flow.src_ip} made ${Math.round(f.repeat_connections_60s)} login attempts on ${flow.dst_ip} within a minute`;
    default:
      return `Unusual traffic from ${flow.src_ip}`;
  }
}

export function timeAgo(iso, now = Date.now()) {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const clock = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");

export const ACTION_LABEL = { block: "Block", allow: "Allow", monitor: "Keep watching" };
export const TTL_OPTIONS = [
  { minutes: 15, label: "15 minutes" },
  { minutes: 60, label: "1 hour" },
  { minutes: 1440, label: "24 hours" },
];
export const COMMAND_STATE = {
  pending: "Waiting for the agent",
  applied: "Done on the machine",
  failed: "Agent could not do it",
  expired: "Block ended",
  reverted: "Undone",
};

// The address a person blocks or trusts: the attacker for scans and floods, the remote address for regular check-ins.
export function offenderIp(alert) {
  const { flow, rule } = alert.evidence;
  return rule?.hit && rule.list_name === "beaconing" ? flow.dst_ip : flow.src_ip;
}
