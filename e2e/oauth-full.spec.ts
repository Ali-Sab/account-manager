// Full OAuth PKCE flow: authorize → code → token exchange → refresh rotation.
// Also covers: SSO skip (authed cookie), denial, logout, discovery endpoints.
import { test, expect } from "@playwright/test";
import * as crypto from "crypto";
import { apiSetup, apiLogin, generateTOTP, getOAuthClientSecret, BASE, getGamebacklogRedirectUri } from "./helpers";

function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// Obtain an auth code via POST /authorize (credentials in form).
async function getAuthCode(
  request: any,
  username: string,
  password: string,
  totpSecret: string,
  redirectUri: string,
  challenge: string,
  state = "teststate"
): Promise<string> {
  const authorizeURL =
    `${BASE}/authorize?client_id=gamebacklog-web` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`;

  const getResp = await request.get(authorizeURL);
  const html = await getResp.text();
  const csrfMatch = html.match(/name="_csrf"\s+value="([^"]+)"/);
  const csrfToken = csrfMatch?.[1] ?? "";

  const postResp = await request.post(`${BASE}/authorize`, {
    form: {
      client_id: "gamebacklog-web",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      decision: "allow",
      username,
      password,
      totp: generateTOTP(totpSecret),
      _csrf: csrfToken,
    },
    maxRedirects: 0,
  });
  const location = postResp.headers()["location"] ?? "";
  const match = location.match(/[?&]code=([^&]+)/);
  if (!match) throw new Error(`No code in redirect: ${location}`);
  return match[1];
}

test.describe("OAuth full flow", () => {
  let totpSecret: string;
  let redirectUri: string;
  let clientSecret: string;

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    totpSecret = account.totpSecret;
    redirectUri = getGamebacklogRedirectUri();
    clientSecret = getOAuthClientSecret("gamebacklog-web");
  });

  // ── Discovery ─────────────────────────────────────────────────────────────────

  test("/.well-known/oauth-protected-resource returns required fields", async ({ request }) => {
    const resp = await request.get(`${BASE}/.well-known/oauth-protected-resource`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.resource).toBeTruthy();
    expect(Array.isArray(body.authorization_servers)).toBe(true);
    expect(body.authorization_servers[0]).toContain("localhost");
  });

  test("/.well-known/oauth-protected-resource supports path suffix", async ({ request }) => {
    const resp = await request.get(`${BASE}/.well-known/oauth-protected-resource/mcp`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.resource).toContain("/mcp");
  });

  test("discovery endpoint includes end_session_endpoint", async ({ request }) => {
    const resp = await request.get(`${BASE}/.well-known/oauth-authorization-server`);
    const meta = await resp.json();
    expect(meta.end_session_endpoint).toContain("/logout");
  });

  // ── Authorization code flow ───────────────────────────────────────────────────

  test("full PKCE flow: auth code → POST /token → access_token + refresh_token", async ({
    request,
  }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    expect(tokenResp.ok()).toBe(true);
    const body = await tokenResp.json();
    expect(body.access_token).toBeTruthy();
    expect(body.refresh_token).toBeTruthy();
    expect(body.token_type).toBe("bearer");
    expect(typeof body.expires_in).toBe("number");
  });

  test("issued JWT has correct audience (gamebacklog)", async ({ request }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    const { access_token } = await tokenResp.json();

    // Decode the JWT payload (no signature check — we just want the claims).
    const [, payloadB64] = access_token.split(".");
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    // aud may be a string or a single-element array depending on the JWT library.
    const aud = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
    expect(aud).toBe("gamebacklog");
    expect(payload.sub).toBe("alice");
  });

  test("POST /token with wrong code_verifier returns invalid_grant", async ({ request }) => {
    const { challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: crypto.randomBytes(32).toString("base64url"), // wrong verifier
      },
    });
    expect(tokenResp.status()).toBe(400);
    expect((await tokenResp.json()).error).toContain("invalid_grant");
  });

  test("POST /token with wrong client_secret returns invalid_client", async ({ request }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: "totallywrongsecret",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    expect(tokenResp.status()).toBe(401);
  });

  test("POST /token with replayed auth code returns invalid_grant", async ({ request }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const params = {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    };

    const first = await request.post(`${BASE}/token`, params);
    expect(first.ok()).toBe(true);

    const second = await request.post(`${BASE}/token`, params);
    expect(second.status()).toBe(400); // code already consumed
  });

  test("POST /token with unsupported grant_type returns error", async ({ request }) => {
    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "client_credentials",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
      },
    });
    expect(tokenResp.status()).toBe(400);
  });

  test("POST /token with unknown client_id returns invalid_client", async ({ request }) => {
    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "nonexistent-client",
        client_secret: "secret",
        code: "fakecode",
        redirect_uri: redirectUri,
        code_verifier: crypto.randomBytes(32).toString("base64url"),
      },
    });
    expect(tokenResp.status()).toBe(401);
  });

  // ── Token refresh + rotation ──────────────────────────────────────────────────

  test("refresh_token grant returns new access_token and rotates refresh_token", async ({
    request,
  }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    const { refresh_token: originalRT } = await tokenResp.json();

    // Use the refresh token to get new tokens.
    const refreshResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "refresh_token",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        refresh_token: originalRT,
      },
    });
    expect(refreshResp.ok()).toBe(true);
    const refreshBody = await refreshResp.json();
    expect(refreshBody.access_token).toBeTruthy();
    expect(refreshBody.refresh_token).toBeTruthy();
    expect(refreshBody.refresh_token).not.toBe(originalRT);
  });

  test("replayed refresh_token returns invalid_grant (rotation invalidates old token)", async ({
    request,
  }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    const { refresh_token } = await tokenResp.json();

    // Use once — rotates.
    await request.post(`${BASE}/token`, {
      form: {
        grant_type: "refresh_token",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        refresh_token,
      },
    });

    // Replay the original token — should fail.
    const replayResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "refresh_token",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        refresh_token,
      },
    });
    expect(replayResp.status()).toBe(400);
  });

  // ── SSO skip ──────────────────────────────────────────────────────────────────

  test("GET /authorize with valid session cookie skips consent and redirects with code", async ({
    request,
  }) => {
    // apiLogin sets the refreshToken cookie in this request context.
    await apiLogin(request, BASE, "alice", "password1234", totpSecret);

    const { challenge } = pkce();
    const resp = await request.get(
      `${BASE}/authorize?client_id=gamebacklog-web` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&state=sso`,
      { maxRedirects: 0 }
    );
    expect(resp.status()).toBe(302);
    const location = resp.headers()["location"] ?? "";
    expect(location).toContain("code=");
    expect(location).toContain("state=sso");
  });

  // ── Denial ────────────────────────────────────────────────────────────────────

  test("POST /authorize with decision=deny redirects with error=access_denied", async ({
    request,
  }) => {
    const { challenge } = pkce();
    const authorizeURL =
      `${BASE}/authorize?client_id=gamebacklog-web` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256&state=denied`;

    const getResp = await request.get(authorizeURL);
    const html = await getResp.text();
    const csrfMatch = html.match(/name="_csrf"\s+value="([^"]+)"/);
    const csrfToken = csrfMatch?.[1] ?? "";

    const postResp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "denied",
        decision: "deny",
        username: "alice",
        password: "password1234",
        totp: generateTOTP(totpSecret),
        _csrf: csrfToken,
      },
      maxRedirects: 0,
    });
    const location = postResp.headers()["location"] ?? "";
    expect(location).toContain("error=access_denied");
    expect(location).toContain("state=denied");
  });

  test("POST /authorize with wrong password re-renders login form (not a redirect)", async ({
    request,
  }) => {
    const { challenge } = pkce();
    const authorizeURL =
      `${BASE}/authorize?client_id=gamebacklog-web` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`;

    const getResp = await request.get(authorizeURL);
    const html = await getResp.text();
    const csrfMatch = html.match(/name="_csrf"\s+value="([^"]+)"/);
    const csrfToken = csrfMatch?.[1] ?? "";

    const postResp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        decision: "allow",
        username: "alice",
        password: "wrongpassword",
        totp: "000000",
        _csrf: csrfToken,
      },
      maxRedirects: 0,
    });
    // Server re-renders the form with an error — 200, not a redirect.
    expect(postResp.status()).toBe(200);
    const errorHtml = await postResp.text();
    expect(errorHtml).toContain("Incorrect username or password");
  });

  test("wrong password: re-rendered form has fresh CSRF — retry with correct credentials redirects with code", async ({
    request,
  }) => {
    const { challenge } = pkce();
    const authorizeURL =
      `${BASE}/authorize?client_id=gamebacklog-web` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`;

    const getResp = await request.get(authorizeURL);
    const csrf1 = (await getResp.text()).match(/name="_csrf"\s+value="([^"]+)"/)![1];

    const badResp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        decision: "allow",
        username: "alice",
        password: "wrongpassword",
        totp: "000000",
        _csrf: csrf1,
      },
      maxRedirects: 0,
    });
    expect(badResp.status()).toBe(200);
    const errorHtml = await badResp.text();
    const csrf2 = errorHtml.match(/name="_csrf"\s+value="([^"]+)"/)![1];
    expect(csrf2).toBeTruthy();

    const goodResp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        decision: "allow",
        username: "alice",
        password: "password1234",
        totp: generateTOTP(totpSecret),
        _csrf: csrf2,
      },
      maxRedirects: 0,
    });
    expect(goodResp.status()).toBe(302);
    expect(goodResp.headers()["location"]).toContain("code=");
  });

  test("wrong TOTP: re-rendered form has fresh CSRF — retry with correct TOTP redirects with code", async ({
    request,
  }) => {
    const { challenge } = pkce();
    const authorizeURL =
      `${BASE}/authorize?client_id=gamebacklog-web` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`;

    const getResp = await request.get(authorizeURL);
    const csrf1 = (await getResp.text()).match(/name="_csrf"\s+value="([^"]+)"/)![1];

    const badResp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        decision: "allow",
        username: "alice",
        password: "password1234",
        totp: "000000",
        _csrf: csrf1,
      },
      maxRedirects: 0,
    });
    expect(badResp.status()).toBe(200);
    const errorHtml = await badResp.text();
    expect(errorHtml).toContain("Incorrect 2FA code");
    const csrf2 = errorHtml.match(/name="_csrf"\s+value="([^"]+)"/)![1];
    expect(csrf2).toBeTruthy();

    const goodResp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        decision: "allow",
        username: "alice",
        password: "password1234",
        totp: generateTOTP(totpSecret),
        _csrf: csrf2,
      },
      maxRedirects: 0,
    });
    expect(goodResp.status()).toBe(302);
    expect(goodResp.headers()["location"]).toContain("code=");
  });

  // ── Logout ────────────────────────────────────────────────────────────────────

  test("GET /logout clears session cookie and returns HTML page", async ({ request }) => {
    await apiLogin(request, BASE, "alice", "password1234", totpSecret);

    const resp = await request.get(`${BASE}/logout`);
    expect(resp.ok()).toBe(true);
    const html = await resp.text();
    expect(html).toContain("signed out");

    // Cookie should be cleared — refresh must now fail.
    const csrfResp = await request.get(`${BASE}/api/auth/csrf`);
    const { csrfToken } = await csrfResp.json();
    const refreshResp = await request.post(`${BASE}/api/auth/refresh`, {
      headers: { "X-CSRF-Token": csrfToken },
    });
    expect(refreshResp.status()).toBe(401);
  });

  test("GET /logout with valid post_logout_redirect_uri shows continue link", async ({
    request,
  }) => {
    // The redirect URI is localhost:3000 (same origin as gamebacklog-web's registered URI).
    const postLogoutURI = "http://localhost:3000/after-logout";
    const resp = await request.get(
      `${BASE}/logout?post_logout_redirect_uri=${encodeURIComponent(postLogoutURI)}`
    );
    expect(resp.ok()).toBe(true);
    const html = await resp.text();
    expect(html).toContain(postLogoutURI);
  });

  test("GET /logout with unregistered redirect URI origin returns 400", async ({ request }) => {
    const resp = await request.get(
      `${BASE}/logout?post_logout_redirect_uri=${encodeURIComponent("http://evil.com/steal")}`
    );
    expect(resp.status()).toBe(400);
  });

  test("GET /logout with malformed redirect URI returns 400", async ({ request }) => {
    const resp = await request.get(
      `${BASE}/logout?post_logout_redirect_uri=not-a-uri`
    );
    expect(resp.status()).toBe(400);
  });

  // ── /oauth/* alias routes ─────────────────────────────────────────────────────

  // ── redirect_uri validation ───────────────────────────────────────────────────

  test("GET /authorize with unregistered redirect_uri returns 400", async ({ request }) => {
    const { challenge } = pkce();
    const resp = await request.get(
      `${BASE}/authorize?client_id=gamebacklog-web` +
        `&redirect_uri=${encodeURIComponent("http://evil.com/steal")}` +
        `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`,
      { maxRedirects: 0 }
    );
    expect(resp.status()).toBe(400);
  });

  test("POST /authorize with unregistered redirect_uri returns 400", async ({ request }) => {
    const { challenge } = pkce();
    const getResp = await request.get(
      `${BASE}/authorize?client_id=gamebacklog-web` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`
    );
    const csrfToken = (await getResp.text()).match(/name="_csrf"\s+value="([^"]+)"/)![1];

    const resp = await request.post(`${BASE}/authorize`, {
      form: {
        client_id: "gamebacklog-web",
        redirect_uri: "http://evil.com/steal",
        code_challenge: challenge,
        code_challenge_method: "S256",
        decision: "allow",
        username: "alice",
        password: "password1234",
        totp: generateTOTP(totpSecret),
        _csrf: csrfToken,
      },
      maxRedirects: 0,
    });
    expect(resp.status()).toBe(400);
  });

  // ── refresh_token grant edge cases ────────────────────────────────────────────

  test("refresh_token grant with wrong client_secret returns 401", async ({ request }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    const { refresh_token } = await tokenResp.json();

    const refreshResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "refresh_token",
        client_id: "gamebacklog-web",
        client_secret: "totallywrongsecret",
        refresh_token,
      },
    });
    expect(refreshResp.status()).toBe(401);
  });

  test("refresh_token grant with unknown client_id returns 401", async ({ request }) => {
    const { verifier, challenge } = pkce();
    const code = await getAuthCode(request, "alice", "password1234", totpSecret, redirectUri, challenge);

    const tokenResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: "gamebacklog-web",
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    const { refresh_token } = await tokenResp.json();

    const refreshResp = await request.post(`${BASE}/token`, {
      form: {
        grant_type: "refresh_token",
        client_id: "nonexistent-client",
        client_secret: "anysecret",
        refresh_token,
      },
    });
    expect(refreshResp.status()).toBe(401);
  });

  // ── /oauth/* alias routes ─────────────────────────────────────────────────────

  test("/oauth/authorize aliases /authorize (GET renders consent page)", async ({ request }) => {
    const { challenge } = pkce();
    const resp = await request.get(
      `${BASE}/oauth/authorize?client_id=gamebacklog-web` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`
    );
    expect(resp.ok()).toBe(true);
    const html = await resp.text();
    expect(html).toContain("Authorize");
  });

  test("GET /token returns probe response", async ({ request }) => {
    const resp = await request.get(`${BASE}/token`);
    expect(resp.ok()).toBe(true);
    expect((await resp.json()).token_endpoint).toBe(true);
  });
});
