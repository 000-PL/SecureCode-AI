// Thin fetch wrapper: adds the JWT, turns network problems into readable messages.
const BASE = import.meta.env.VITE_API_URL || "/api";
const KEY = "sc_token";

let token = localStorage.getItem(KEY) || "";
export const getToken = () => token;
export function setToken(t) {
  token = t || "";
  if (token) localStorage.setItem(KEY, token);
  else localStorage.removeItem(KEY);
}

export class ApiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.status = status;
  }
}

function formatDetail(detail) {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        const field = Array.isArray(d.loc) ? d.loc[d.loc.length - 1] : "";
        return field && field !== "body" ? `${field}: ${d.msg}` : d.msg;
      })
      .join("; ");
  }
  return JSON.stringify(detail);
}

async function send(path, { method = "GET", body, signal } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(BASE + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (e) {
    if (e && e.name === "AbortError") throw e;
    throw new ApiError("Cannot reach the backend server. Start it with run.bat / run.sh (see README) and try again.", 0);
  }
  if (res.status === 401 && token && !path.startsWith("/auth/login") && !path.startsWith("/auth/register")) {
    setToken("");
    window.dispatchEvent(new Event("sc-logout"));
  }
  return res;
}

async function parse(res) {
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) throw new ApiError(formatDetail(data && data.detail) || `Request failed (${res.status})`, res.status);
  return data;
}

export async function api(path, opts) {
  return parse(await send(path, opts));
}

export async function downloadFile(path, fallbackName) {
  const res = await send(path);
  if (!res.ok) await parse(res);
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const m = /filename="?([^";]+)"?/.exec(cd);
  const name = m ? m[1] : fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
