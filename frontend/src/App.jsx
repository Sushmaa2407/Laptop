import { useEffect, useMemo, useState } from "react";
import { getAgents, getAlert, getAlerts, getStats, hasToken, logout, setAuthLostHandler } from "./api.js";
import CaseFile from "./CaseFile.jsx";
import Login from "./Login.jsx";
import Queue from "./Queue.jsx";
import { usePoll } from "./usePoll.js";
import { SEVERITY_ORDER, timeAgo } from "./util.js";

function Dashboard({ onSignOut }) {
  const [filter, setFilter] = useState("open");
  const [selectedId, setSelectedId] = useState(null);

  const stats = usePoll(getStats, 3000);
  const agents = usePoll(getAgents, 5000);
  const alerts = usePoll(() => getAlerts(filter), 2500, [filter]);

  const sorted = useMemo(() => {
    if (!alerts.data) return null;
    return [...alerts.data].sort(
      (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || new Date(b.created_at) - new Date(a.created_at),
    );
  }, [alerts.data]);

  // Pick the most serious alert when nothing is chosen yet.
  useEffect(() => {
    if (!selectedId && sorted?.length) setSelectedId(sorted[0].id);
  }, [sorted, selectedId]);

  // The open case is polled on its own, so it stays visible (with its response log) after it leaves the list.
  const detail = usePoll(() => (selectedId ? getAlert(selectedId) : Promise.resolve(null)), 2000, [selectedId]);
  const selected = detail.data && detail.data.id === selectedId ? detail.data : null;
  const online = agents.data?.filter((a) => a.last_seen_at && Date.now() - new Date(a.last_seen_at).getTime() < 45000) ?? [];
  const connError = alerts.error || stats.error;

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">Laptop Shield</span>
        <p className="statusline" aria-live="polite">
          {stats.data ? (
            <>
              <strong>{stats.data.open_alerts}</strong> open · <strong>{stats.data.alerts_24h}</strong> in the last 24 h ·{" "}
              <strong>{stats.data.flows_5m}</strong> connections seen in 5 min
            </>
          ) : (
            "Connecting…"
          )}
        </p>
        <div className="agents">
          {agents.data?.filter((a) => a.status === "active").map((a) => {
            const up = online.some((o) => o.id === a.id);
            return (
              <span key={a.id} className="agent" title={`Last heard ${timeAgo(a.last_seen_at)}`}>
                <span className={`dot ${up ? "up" : "down"}`} aria-hidden="true" />
                {a.name} <span className="muted">{up ? "online" : `offline, last heard ${timeAgo(a.last_seen_at)}`}</span>
              </span>
            );
          })}
        </div>
        <button className="btn ghost" onClick={onSignOut}>Sign out</button>
      </header>

      {connError && <p role="alert" className="banner">{connError.message}</p>}

      <div className="layout">
        <Queue
          alerts={sorted}
          filter={filter}
          onFilter={(f) => {
            setFilter(f);
            setSelectedId(null);
          }}
          selectedId={selectedId}
          onSelect={setSelectedId}
          loading={alerts.data === null && !alerts.error}
          agentName={online[0]?.name}
        />
        <CaseFile
          alert={selected}
          onChanged={() => {
            alerts.reload();
            detail.reload();
            stats.reload();
          }}
          key={selectedId}
        />
      </div>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(hasToken());
  useEffect(() => setAuthLostHandler(() => setAuthed(false)), []);
  if (!authed) return <Login onSuccess={() => setAuthed(true)} />;
  return (
    <Dashboard
      onSignOut={async () => {
        await logout();
        setAuthed(false);
      }}
    />
  );
}
