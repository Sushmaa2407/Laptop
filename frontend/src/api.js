// Thin client for the Shield API. The access token lives in sessionStorage (cleared when the tab closes);
// when it expires we try the refresh cookie once, then send the person back to the login screen.
const BASE = "/api/v1";
const KEY = "shield_token";

let token = null;
try {
  token = sessionStorage.getItem(KEY);
} catch {
  token = null;
}
let onAuthLost = () => {};

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function saveToken(value) {
  token = value;
  try {
    if (value) sessionStorage.setItem(KEY, value);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: the token just stays in memory */
  }
}

async function detailOf(res) {
  try {
    const body = await res.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) return body.detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
  } catch {
    /* not JSON */
  }
  return `Request failed (${res.status})`;
}

async function refresh() {
  try {
    const res = await fetch(`${BASE}/auth/refresh`, { method: "POST", credentials: "include" });
    if (!res.ok) return false;
    const body = await res.json();
    if (!body.access_token) return false;
    saveToken(body.access_token);
    return true;
  } catch {
    return false;
  }
}

async function request(path, { method = "GET", body, retry = true } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(BASE + path, {
      method,
      headers,
      credentials: "include",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "Cannot reach the Shield server. Is the stack running?");
  }
  if (res.status === 401 && retry && !path.startsWith("/auth/")) {
    if (await refresh()) return request(path, { method, body, retry: false });
    saveToken(null);
    onAuthLost();
    throw new ApiError(401, "Your session expired. Sign in again.");
  }
  if (!res.ok) throw new ApiError(res.status, await detailOf(res));
  return res.status === 204 ? null : res.json();
}

export const setAuthLostHandler = (fn) => {
  onAuthLost = fn;
};
export const hasToken = () => Boolean(token);

export async function login(email, password) {
  const data = await request("/auth/login", { method: "POST", body: { email, password } });
  if (!data?.access_token) throw new ApiError(500, "The server did not return a token.");
  saveToken(data.access_token);
}

export async function register(tenantName, email, password) {
  await request("/auth/register", { method: "POST", body: { email, password, tenant_name: tenantName } });
  await login(email, password);
}

export async function logout() {
  try {
    await request("/auth/logout", { method: "POST" });
  } catch {
    /* signing out must always work locally */
  }
  saveToken(null);
}

export const getStats = () => request("/stats");
export const getAgents = () => request("/agents");
export const getAlerts = (status) => request(`/alerts?limit=100${status && status !== "all" ? `&status=${status}` : ""}`);
export const getAlert = (id) => request(`/alerts/${id}`);
export const getAlertCommands = (id) => request(`/alerts/${id}/commands`);
export const decideAlert = (id, action, ttlMinutes) =>
  request(`/alerts/${id}/decision`, { method: "POST", body: { action, ttl_minutes: ttlMinutes } });
export const unblockAlert = (id) => request(`/alerts/${id}/unblock`, { method: "POST" });
export const createEnrollmentCode = (agentName) =>
  request("/agents/enrollment-codes", { method: "POST", body: { agent_name: agentName } });
