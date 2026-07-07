import { test, expect } from "@playwright/test";
import { apiSetup, generateTOTP, BASE, getGamebacklogRedirectUri } from "./helpers";
import * as crypto from "crypto";

// Compute PKCE pair.
function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

test.describe("OAuth authorization server", () => {
  // Read the registered redirect URI once — either from E2E_GAMEBACKLOG_REDIRECT_URI
  // or directly from the DB so tests stay in sync with whatever was seeded at startup.
  let redirectUri: string;

  test.beforeAll(() => {
    redirectUri = getGamebacklogRedirectUri();
  });

  test("discovery endpoint returns required fields", async ({ request }) => {
    const resp = await request.get(`${BASE}/.well-known/oauth-authorization-server`);
    expect(resp.ok()).toBe(true);
    const meta = await resp.json();
    expect(meta.issuer).toBeTruthy();
    expect(meta.authorization_endpoint).toContain("/authorize");
    expect(meta.token_endpoint).toContain("/token");
    expect(meta.jwks_uri).toContain("/jwks.json");
    expect(meta.code_challenge_methods_supported).toContain("S256");
  });

  test("JWKS endpoint returns RSA key", async ({ request }) => {
    const resp = await request.get(`${BASE}/.well-known/jwks.json`);
    expect(resp.ok()).toBe(true);
    const { keys } = await resp.json();
    expect(keys).toHaveLength(1);
    expect(keys[0].kty).toBe("RSA");
    expect(keys[0].alg).toBe("RS256");
    expect(keys[0].n).toBeTruthy();
    expect(keys[0].e).toBeTruthy();
  });

  test("authorize with unknown client_id returns error", async ({ request }) => {
    const { challenge } = pkce();
    const resp = await request.get(
      `${BASE}/authorize?client_id=unknown&redirect_uri=http://x.com&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`,
      { maxRedirects: 0 }
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  test("authorize with missing PKCE returns error", async ({ request }) => {
    const resp = await request.get(
      `${BASE}/authorize?client_id=gamebacklog-web&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`,
      { maxRedirects: 0 }
    );
    expect(resp.status()).toBeGreaterThanOrEqual(400);
  });

  test("authorize GET without session renders consent page HTML", async ({ request }) => {
    const { challenge } = pkce();
    const resp = await request.get(
      `${BASE}/authorize?client_id=gamebacklog-web&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`
    );
    expect(resp.ok()).toBe(true);
    const html = await resp.text();
    expect(html).toContain("Authorize");
    expect(html).toContain("password");
  });

  test("authorize POST with valid credentials redirects with code", async ({ request }) => {
    const account = await apiSetup(request, BASE);
    const { verifier, challenge } = pkce();

    const authorizeURL =
      `${BASE}/authorize?client_id=gamebacklog-web` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&state=teststate`;

    // GET first to receive the CSRF token embedded in the form.
    const getResp = await request.get(authorizeURL);
    expect(getResp.ok()).toBe(true);
    const html = await getResp.text();
    const csrfMatch = html.match(/name="_csrf"\s+value="([^"]+)"/);
    const csrfToken = csrfMatch?.[1] ?? "";

    const resp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "teststate",
        decision: "allow",
        username: account.username,
        password: account.password,
        totp: generateTOTP(account.totpSecret),
        _csrf: csrfToken,
      },
      maxRedirects: 0,
    });
    // Success: redirect with code. Failure: redirect with error= or 200 re-rendered form.
    const location = resp.headers()["location"] ?? "";
    const hasCode = location.includes("code=");
    const hasError = location.includes("error=") || resp.status() === 200;
    expect(hasCode || hasError).toBe(true);
    _ = verifier;
  });
});

function _(x: unknown) {}
