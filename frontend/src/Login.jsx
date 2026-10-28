import { useState } from "react";
import { login, register } from "./api.js";

export default function Login({ onSuccess }) {
  const [mode, setMode] = useState("login");
  const [tenant, setTenant] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const creating = mode === "register";

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (creating) await register(tenant.trim(), email.trim(), password);
      else await login(email.trim(), password);
      onSuccess();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form onSubmit={submit} className="login-form" aria-labelledby="login-title">
        <h1 id="login-title" className="brand-large">Laptop Shield</h1>
        <p className="muted">
          {creating
            ? "Create your own workspace. Your devices and alerts stay private to it."
            : "Sign in to see what is happening on your protected machines."}
        </p>
        {creating && (
          <label>
            Workspace name
            <input value={tenant} onChange={(e) => setTenant(e.target.value)} maxLength={100} required autoFocus />
          </label>
        )}
        <label>
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus={!creating} />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={creating ? "new-password" : "current-password"} maxLength={128} required />
        </label>
        {error && <p role="alert" className="form-error">{error}</p>}
        <button className="btn primary" disabled={busy}>
          {busy ? "Please wait…" : creating ? "Create account" : "Sign in"}
        </button>
        <button type="button" className="btn ghost" onClick={() => { setMode(creating ? "login" : "register"); setError(""); }}>
          {creating ? "I already have an account" : "Create an account"}
        </button>
      </form>
    </main>
  );
}
