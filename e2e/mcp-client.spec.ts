// POST /api/mcp-client — returns the claude-mcp OAuth client credentials so
// downstream services (e.g. game-backlog) can surface them in their settings UI.
// Authenticated via HTTP Basic auth with the gamebacklog-web client credentials; other clients get 403.
import { test, expect } from "@playwright/test";
import { apiSetup, BASE, getOAuthClientSecret } from "./helpers";

test.describe("/api/mcp-client", () => {
  let clientSecret: string;

  test.beforeAll(async ({ request }) => {
    await apiSetup(request, BASE);
    clientSecret = getOAuthClientSecret("gamebacklog-web");
  });

  test("POST without Authorization header returns 401", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/mcp-client`);
    expect(resp.status()).toBe(401);
  });

  test("POST with wrong client_secret returns 401", async ({ request }) => {
    const creds = Buffer.from("gamebacklog-web:wrongsecret").toString("base64");
    const resp = await request.post(`${BASE}/api/mcp-client`, {
      headers: { Authorization: `Basic ${creds}` },
    });
    expect(resp.status()).toBe(401);
  });

  test("POST with unknown client_id returns 401", async ({ request }) => {
    const creds = Buffer.from("nonexistent-client:anysecret").toString("base64");
    const resp = await request.post(`${BASE}/api/mcp-client`, {
      headers: { Authorization: `Basic ${creds}` },
    });
    expect(resp.status()).toBe(401);
  });

  test("POST with correct credentials returns claude-mcp client info", async ({ request }) => {
    const creds = Buffer.from(`gamebacklog-web:${clientSecret}`).toString("base64");
    const resp = await request.post(`${BASE}/api/mcp-client`, {
      headers: { Authorization: `Basic ${creds}` },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.client_id).toBe("claude-mcp");
    expect(typeof body.client_secret).toBe("string");
  });

  test("POST with a redirect_uri body leaves the registered URI unchanged", async ({ request }) => {
    const creds = Buffer.from(`gamebacklog-web:${clientSecret}`).toString("base64");
    const otherUri = "http://localhost:3000/auth/callback-other";

    const resp = await request.post(`${BASE}/api/mcp-client`, {
      headers: { Authorization: `Basic ${creds}` },
      data: { redirect_uri: otherUri },
    });
    expect(resp.ok()).toBe(true);

    const { createHash, randomBytes } = await import("crypto");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = (redirectUri: string) =>
      request.get(
        `${BASE}/authorize?client_id=gamebacklog-web` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`,
        { maxRedirects: 0 }
      );

    expect((await authorize(otherUri)).status()).toBe(400);
    expect((await authorize("http://localhost:3000/auth/callback")).ok()).toBe(true);
  });

  test("POST with another client's valid credentials returns 403", async ({ request }) => {
    const otherSecret = getOAuthClientSecret("chore-chart");
    const creds = Buffer.from(`chore-chart:${otherSecret}`).toString("base64");
    const resp = await request.post(`${BASE}/api/mcp-client`, {
      headers: { Authorization: `Basic ${creds}` },
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.client_secret).toBeUndefined();
  });
});
