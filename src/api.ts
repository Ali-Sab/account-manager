let _accessToken: string | null = null;
let _csrfToken:   string | null = null;
let _refreshing = false;

export function setAccessToken(t: string | null) { _accessToken = t; }
export function getAccessToken() { return _accessToken; }
export function setCsrfToken(t: string | null)   { _csrfToken = t; }

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

  const res = await fetch(path, {
    method,
    headers,
    credentials: "include",
    body: body != null ? JSON.stringify(body) : undefined,
  });

  // Attempt one silent refresh on 401
  if (res.status === 401 && auth && !_isRetry && !_refreshing) {
    _refreshing = true;
    try {
      const refreshed = await api("POST", "/api/auth/refresh", undefined, false);
      if (typeof refreshed.accessToken === "string") {
        _accessToken = refreshed.accessToken;
        _refreshing  = false;
        return api(method, path, body, auth, true);
      }
    } catch { /* fall through */ }
    _refreshing = false;
  }

  if (!res.ok && !res.headers.get("content-type")?.includes("application/json")) {
    return { error: `Server error ${res.status}` };
  }
  return res.json() as Promise<Record<string, unknown>>;
}

export async function fetchCsrfToken(): Promise<void> {
  try {
    const data = await api("GET", "/api/auth/csrf", undefined, false);
    if (typeof data.csrfToken === "string") _csrfToken = data.csrfToken;
  } catch { /* ignore */ }
}
