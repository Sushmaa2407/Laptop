import { useState } from "react";
import { decideAlert, getAlertCommands, unblockAlert } from "./api.js";
import { usePoll } from "./usePoll.js";
import { ACTION_LABEL, COMMAND_STATE, KIND_LABEL, TTL_OPTIONS, clock, conflictText, featureLabel, headline, kindOf, offenderIp } from "./util.js";

function Gauge({ score, threshold }) {
  const pct = (v) => `${Math.min(100, Math.max(0, v * 100))}%`;
  return (
    <div className="gauge" role="img" aria-label={`Anomaly score ${score.toFixed(2)}, alert line ${threshold.toFixed(2)}`}>
      <div className="gauge-track">
        <div className="gauge-fill" style={{ width: pct(score) }} data-over={score >= threshold} />
        <div className="gauge-line" style={{ left: pct(threshold) }} />
      </div>
      <div className="gauge-scale">
        <span>normal</span>
        <span>unusual</span>
      </div>
    </div>
  );
}

function Explanation({ alert }) {
  const ex = alert.explanation;
  if (alert.explanation_status === "pending" || !ex) {
    return (
      <section className="block">
        <h3>What the assistant says</h3>
        <p className="muted">Writing an explanation… the local model can take a few seconds.</p>
      </section>
    );
  }
  return (
    <section className="block">
      <h3>What the assistant says</h3>
      <p className="explain">{ex.summary}</p>
      <ul className="reasons">
        {ex.reasons.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
      <p className="meta-line">
        <span className={`chip ${ex.recommended_action}`}>Suggests: {ACTION_LABEL[ex.recommended_action]}</span>
        <span className="muted">
          {ex.source === "llm" ? `Written by ${ex.model}` : "Standard wording (the language model was not available)"}. Advice only: you decide.
        </span>
      </p>
    </section>
  );
}

function Evidence({ alert }) {
  const { rule, anomaly, key_features, conflicts, flow, temporal } = alert.evidence;
  return (
    <section className="block">
      <h3>Evidence</h3>
      <div className="evidence-grid">
        <div>
          <p className="label">Fixed rules</p>
          <p>{rule.hit ? `Matched: ${KIND_LABEL[rule.list_name] || rule.list_name}` : "No rule matched"}</p>
        </div>
        <div>
          <p className="label">Learning model</p>
          <p>
            {anomaly.score.toFixed(2)} <span className="muted">(alert line {anomaly.threshold.toFixed(2)})</span>
          </p>
          <Gauge score={anomaly.score} threshold={anomaly.threshold} />
        </div>
        {temporal?.is_periodic && (
          <div>
            <p className="label">Timing</p>
            <p>
              Regular rhythm <span className="muted">(score {temporal.periodicity_score.toFixed(2)}, {temporal.events_seen} contacts)</span>
            </p>
          </div>
        )}
        <div>
          <p className="label">Connection</p>
          <p className="mono">
            {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port} {flow.protocol}
          </p>
        </div>
      </div>
      {conflicts.length > 0 && (
        <ul className="conflicts">
          {conflicts.map((c) => (
            <li key={c}>{conflictText(c)}</li>
          ))}
        </ul>
      )}
      <details>
        <summary>All measurements</summary>
        <dl className="features">
          {key_features.map((f) => (
            <div key={f.name}>
              <dt>{featureLabel(f.name)}</dt>
              <dd>{Number.isInteger(f.value) ? f.value : f.value.toFixed(4)}</dd>
            </div>
          ))}
        </dl>
      </details>
    </section>
  );
}

function Response({ alert }) {
  const active = alert.status === "blocked" || alert.status === "dismissed";
  const { data: commands } = usePoll(() => getAlertCommands(alert.id), 2000, [alert.id, alert.status]);
  if (!active || !commands || commands.length === 0) return null;
  return (
    <section className="block">
      <h3>What was done</h3>
      <ul className="log">
        {commands.map((c) => (
          <li key={c.id}>
            <span className={`dot cmd-${c.state}`} aria-hidden="true" />
            <span>
              {c.type === "block_ip" ? `Block ${c.ip}${c.ttl_minutes ? ` for ${c.ttl_minutes} min` : ""}` : `Unblock ${c.ip}`}
            </span>
            <span className="muted">
              {COMMAND_STATE[c.state] || c.state}
              {c.acked_at ? ` at ${clock(c.acked_at)}` : ""}
              {c.state === "failed" && c.result ? `: ${c.result}` : ""}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export default function CaseFile({ alert, onChanged }) {
  const [confirm, setConfirm] = useState(null);
  const [ttl, setTtl] = useState(60);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (!alert) {
    return (
      <section className="casefile placeholder">
        <p className="muted">Select an alert to see what happened and decide what to do.</p>
      </section>
    );
  }
  const src = offenderIp(alert);

  async function run(action) {
    if (confirm !== action) {
      setConfirm(action);
      return;
    }
    setBusy(true);
    setError("");
    try {
      if (action === "unblock") await unblockAlert(alert.id);
      else await decideAlert(alert.id, action, ttl);
      setConfirm(null);
      onChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className={`casefile sev-${alert.severity}`} onKeyDown={(e) => e.key === "Escape" && setConfirm(null)}>
      <div className="case-grid">
        <div className="case-main">
        <header className="case-head">
          <p className="meta-line">
            <span className={`chip sev ${alert.severity}`}>{alert.severity}</span>
            <span>{KIND_LABEL[kindOf(alert)]}</span>
            <span className="muted">{clock(alert.created_at)}</span>
            {alert.status !== "open" && <span className={`chip st-${alert.status}`}>{alert.status}</span>}
          </p>
          <h2 className="case-title">{headline(alert)}</h2>
        </header>

        <Explanation alert={alert} />

        {alert.status === "open" && (
          <section className="decision" aria-label="Decide what to do">
            <div className="decision-main">
              <label className="ttl">
                Block for
                <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))} disabled={busy}>
                  {TTL_OPTIONS.map((o) => (
                    <option key={o.minutes} value={o.minutes}>{o.label}</option>
                  ))}
                </select>
              </label>
              <button className={`btn primary${confirm === "block" ? " armed" : ""}`} disabled={busy} onClick={() => run("block")}>
                {confirm === "block" ? `Confirm: block ${src}` : `Block ${src}`}
              </button>
              <button className={`btn secondary${confirm === "allow" ? " armed" : ""}`} disabled={busy} onClick={() => run("allow")}>
                {confirm === "allow" ? "Confirm: trust this address" : "Allow"}
              </button>
              <button className="btn ghost" disabled={busy} onClick={() => run("dismiss")}>
                {confirm === "dismiss" ? "Confirm: dismiss" : "Dismiss"}
              </button>
            </div>
            <p className="muted small">
              {confirm === "allow"
                ? `Allow marks ${src} as trusted: it will not raise alerts again. Click again to confirm.`
                : confirm
                  ? "Click the same button again to confirm. Press Esc to cancel."
                  : "Block cuts the address off at the machine's firewall. Allow trusts it from now on. Dismiss just closes the alert."}
            </p>
          </section>
        )}
        {alert.status === "blocked" && (
          <section className="decision">
            <div className="decision-main">
              <button className={`btn secondary${confirm === "unblock" ? " armed" : ""}`} disabled={busy} onClick={() => run("unblock")}>
                {confirm === "unblock" ? "Confirm: unblock now" : "Unblock now"}
              </button>
            </div>
          </section>
        )}
        {error && <p role="alert" className="form-error">{error}</p>}
        </div>
        <div className="case-side">
          <Evidence alert={alert} />
          <Response alert={alert} />
        </div>
      </div>
    </article>
  );
}
