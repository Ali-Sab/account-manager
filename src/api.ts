const API_BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

let _accessToken: string | null = null;
let _csrfToken:   string | null = null;
let _refreshing = false;

export function setAccessToken(t: string | null) { _accessToken = t; }
export function getAccessToken() { return _accessToken; }
export function setCsrfToken(t: string | null)   { _csrfToken = t; }
export function clearSession() { _accessToken = null; _csrfToken = null; }

const TIMEOUT_MS = 15_000;

export async function api(
  method: string,
  path: string,
  body?: unknown,
  auth = true,
  _isRetry = false,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (auth && _accessToken) headers["Authorization"] = `Bearer ${_accessToken}`;
  if (_csrfToken && method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = _csrfToken;

  let res: Response;
  try {
    res = await fetch(API_BASE + path, {
      method,
      headers,
      credentials: "include",
      body: body != null ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e: unknown) {
    const err = e as { name?: string };
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      return { error: "Request timed out. Check your connection and try again." };
    }
    return { error: "Network error. Check your connection and try again." };
  }

  // Attempt one silent refresh on 401
  if (res.status === 401 && auth && !_isRetry && !_refreshing) {
    _refreshing = true;
    try {
      const refreshed = await api("POST", "/api/auth/refresh", undefined, false);
      if (typeof refreshed.accessToken === "string") {
        _accessToken = refreshed.accessToken;
        return api(method, path, body, auth, true);
      }
    } catch { /* fall through */ } finally {
      _refreshing = false;
    }
  }

  if (!res.ok && !res.headers.get("content-type")?.includes("application/json")) {
    const msg = res.status === 429
      ? "Too many attempts. Please wait a moment and try again."
      : res.status >= 500
        ? "Server error. Please try again later."
        : `Unexpected error (${res.status}).`;
    return { error: msg };
  }
  return res.json() as Promise<Record<string, unknown>>;
}

export async function fetchCsrfToken(): Promise<void> {
  try {
    const data = await api("GET", "/api/auth/csrf", undefined, false);
    if (typeof data.csrfToken === "string") _csrfToken = data.csrfToken;
  } catch { /* ignore */ }
}
