import { useEffect, useState } from "react";
import { createEnrollmentCode, getAgents } from "./api.js";
import { usePoll } from "./usePoll.js";
import { timeAgo } from "./util.js";

const SERVER_KEY = "shield_public_server";

function installCommand({ server, code, ownCa }) {
  const curl = ownCa ? "curl -fsSLk" : "curl -fsSL";
  const extra = ownCa ? " --fetch-ca" : "";
  return `${curl} ${server}/api/v1/downloads/install.sh | sudo bash -s -- --code ${code}${extra}`;
}

function AddDevice() {
  const [name, setName] = useState("my-laptop");
  const [server, setServer] = useState(() => {
    try {
      return localStorage.getItem(SERVER_KEY) || "https://shield.lab";
    } catch {
      return "https://shield.lab";
    }
  });
  const [ownCa, setOwnCa] = useState(true);
  const [made, setMade] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(SERVER_KEY, server);
    } catch {
      /* ignore */
    }
  }, [server]);

  async function create(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setCopied(false);
    try {
      setMade(await createEnrollmentCode(name.trim()));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const command = made ? installCommand({ server: server.replace(/\/+$/, ""), code: made.code, ownCa }) : "";

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <section className="add-device" aria-labelledby="add-title">
      <h2 id="add-title" className="page-title">Add a laptop</h2>
      <p className="muted">
        Create a one-time install command, then run it on the laptop you want to protect. Only the small sensor is installed;
        everything else runs on the server.
      </p>
      <form onSubmit={create} className="add-form">
        <label>
          Name for this laptop
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required />
        </label>
        <label>
          Server address the laptop will use
          <input value={server} onChange={(e) => setServer(e.target.value)} placeholder="https://shield.example.com" required />
        </label>
        <label className="check">
          <input type="checkbox" checked={ownCa} onChange={(e) => setOwnCa(e.target.checked)} />
          My server uses its own certificate authority (lab setup)
        </label>
        <button className="btn primary" disabled={busy}>{busy ? "Creating…" : "Create install command"}</button>
      </form>
      {error && <p role="alert" className="form-error">{error}</p>}
      {made && (
        <div className="command-box">
          <p>
            Run this on the laptop (Linux with Python 3.11 or newer). The code works once and expires at{" "}
            <strong>{new Date(made.expires_at).toLocaleTimeString()}</strong>.
          </p>
          <pre className="command" tabIndex={0}>{command}</pre>
          <button className="btn secondary" onClick={copy}>{copied ? "Copied" : "Copy command"}</button>
          {ownCa && (
            <p className="muted small">
              With your own certificate authority the first download is not verified; the installer prints the certificate fingerprint so you can compare it. A server with a normal public certificate does not need this.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

export default function Devices() {
  const agents = usePoll(getAgents, 4000);
  const rows = agents.data?.filter((a) => a.status === "active") ?? [];
  const online = (a) => a.last_seen_at && Date.now() - new Date(a.last_seen_at).getTime() < 45000;

  return (
    <main className="devices">
      <AddDevice />
      <section aria-labelledby="list-title">
        <h2 id="list-title" className="page-title">Your devices</h2>
        {agents.error && <p role="alert" className="form-error">{agents.error.message}</p>}
        {agents.data && rows.length === 0 && <p className="muted">No devices yet. Add your first laptop above.</p>}
        <ul className="device-list">
          {rows.map((a) => (
            <li key={a.id} className="device">
              <span className={`dot ${online(a) ? "up" : "down"}`} aria-hidden="true" />
              <span className="device-name">{a.name}</span>
              <span className="muted">
                {online(a) ? "online" : `offline, last heard ${timeAgo(a.last_seen_at)}`}
                {a.platform ? ` · ${a.platform}` : ""}
                {a.version ? ` · sensor ${a.version}` : ""}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
