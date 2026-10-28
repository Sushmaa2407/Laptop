import { useEffect, useRef, useState } from "react";
import { KIND_LABEL, kindOf, offenderIp, timeAgo } from "./util.js";

const TABS = [
  ["open", "Open"],
  ["blocked", "Blocked"],
  ["allowed", "Allowed"],
  ["dismissed", "Dismissed"],
  ["all", "All"],
];

export default function Queue({ alerts, filter, onFilter, selectedId, onSelect, loading, agentName }) {
  const seen = useRef(null);
  const [fresh, setFresh] = useState(new Set());

  // Mark alerts that appeared since the last refresh so a new arrival is noticeable for a few seconds.
  useEffect(() => {
    if (!alerts) return;
    const ids = new Set(alerts.map((a) => a.id));
    if (seen.current) {
      const added = alerts.filter((a) => !seen.current.has(a.id)).map((a) => a.id);
      if (added.length) {
        setFresh((prev) => new Set([...prev, ...added]));
        setTimeout(() => setFresh((prev) => new Set([...prev].filter((id) => !added.includes(id)))), 6000);
      }
    }
    seen.current = ids;
  }, [alerts]);

  return (
    <section className="queue" aria-label="Alerts">
      <div className="tabs" role="tablist">
        {TABS.map(([key, label]) => (
          <button key={key} role="tab" aria-selected={filter === key} className={filter === key ? "tab on" : "tab"} onClick={() => onFilter(key)}>
            {label}
          </button>
        ))}
      </div>
      <ul className="queue-list" aria-live="polite">
        {alerts?.map((a) => (
          <li key={a.id}>
            <button className={`q-item sev-${a.severity}${a.id === selectedId ? " selected" : ""}${fresh.has(a.id) ? " fresh" : ""}`} onClick={() => onSelect(a.id)}>
              <span className="q-top">
                <span className="q-kind">{KIND_LABEL[kindOf(a)]}</span>
                <span className="q-sev">{a.severity}</span>
              </span>
              <span className="q-ip">{kindOf(a) === "beaconing" ? `${a.evidence.flow.src_ip} → ${offenderIp(a)}` : a.evidence.flow.src_ip}</span>
              <span className="q-bottom">
                <span>{timeAgo(a.created_at)}</span>
                {a.status !== "open" && <span className={`chip st-${a.status}`}>{a.status}</span>}
                {fresh.has(a.id) && <span className="chip new">new</span>}
              </span>
            </button>
          </li>
        ))}
      </ul>
      {alerts && alerts.length === 0 && (
        <div className="empty">
          <p className="empty-title">{filter === "open" ? "No open alerts" : "Nothing here yet"}</p>
          <p className="muted">
            {filter === "open"
              ? `${agentName ? agentName : "Your agents"} ${agentName ? "is" : "are"} being watched. New threats appear here within seconds.`
              : "Alerts you handle will be listed under this tab."}
          </p>
        </div>
      )}
      {loading && !alerts && <p className="muted pad">Loading alerts…</p>}
    </section>
  );
}
