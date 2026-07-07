// POST /api/mcp-client — returns the claude-mcp OAuth client credentials so
// downstream services (e.g. game-backlog) can surface them in their settings UI.
// Authenticated via HTTP Basic auth using any registered OAuth client's credentials.
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

  test("POST with redirect_uri body updates the caller's registered URI", async ({ request }) => {
    const creds = Buffer.from(`gamebacklog-web:${clientSecret}`).toString("base64");
    const headers = { Authorization: `Basic ${creds}` };
    const updatedUri = "http://localhost:3000/auth/callback-updated";

    const updateResp = await request.post(`${BASE}/api/mcp-client`, {
      headers,
      data: { redirect_uri: updatedUri },
    });
    expect(updateResp.ok()).toBe(true);

    // Verify the URI was updated by attempting a GET /authorize — the new URI
    // should now be accepted, the old one rejected.
    const { createHash, randomBytes } = await import("crypto");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");

    const newUriResp = await request.get(
      `${BASE}/authorize?client_id=gamebacklog-web` +
        `&redirect_uri=${encodeURIComponent(updatedUri)}` +
        `&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`,
      { maxRedirects: 0 }
    );
    expect(newUriResp.ok()).toBe(true);

    // Restore the original redirect URI so the rest of the suite is unaffected.
    const originalUri = "http://localhost:3000/auth/callback";
    await request.post(`${BASE}/api/mcp-client`, {
      headers,
      data: { redirect_uri: originalUri },
    });
  });
});
