// WebAuthn API surface tests that don't require real hardware.
// Full register/login flows require a physical authenticator and can't be automated here.
// What we CAN verify: endpoint availability, pre-conditions, and credential management.
import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, apiCreateUser, BASE } from "./helpers";

test.describe("WebAuthn API surface", () => {
  let adminToken: string;
  let userToken: string;

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    const session = await apiLogin(
      request, BASE, account.username, account.password, account.totpSecret
    );
    adminToken = session.accessToken;

    const user = await apiCreateUser(request, BASE, adminToken, "wauser", "wauserpass123");
    const userSession = await apiLogin(request, BASE, "wauser", "wauserpass123", user.totpSecret);
    userToken = userSession.accessToken;
  });

  test.afterAll(async ({ request }) => {
    await request.delete(`${BASE}/api/admin/users/wauser`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });

  // ── register/start and register/finish (first-run only) ──────────────────────

  test("POST /api/webauthn/register/start returns 403 when server is already configured", async ({
    request,
  }) => {
    const resp = await request.post(`${BASE}/api/webauthn/register/start`, {
      data: { username: "newuser", password: "newuserpass123" },
    });
    expect(resp.status()).toBe(403);
  });

  test("POST /api/webauthn/register/finish returns 403 when server is already configured", async ({
    request,
  }) => {
    const resp = await request.post(`${BASE}/api/webauthn/register/finish`, {
      data: {},
    });
    expect(resp.status()).toBe(403);
  });

  // ── login/start ───────────────────────────────────────────────────────────────

  test("POST /api/webauthn/login/start returns 400 when no passkeys are registered", async ({
    request,
  }) => {
    // On a fresh server with only TOTP-based accounts, there are no passkeys.
    const resp = await request.post(`${BASE}/api/webauthn/login/start`);
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.error).toMatch(/no passkeys/i);
  });

  // ── credentials list ──────────────────────────────────────────────────────────

  test("GET /api/webauthn/credentials returns empty array for account with no passkeys", async ({
    request,
  }) => {
    const resp = await request.get(`${BASE}/api/webauthn/credentials`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    expect(resp.ok()).toBe(true);
    const creds = await resp.json();
    expect(Array.isArray(creds)).toBe(true);
    expect(creds).toHaveLength(0);
  });

  // ── credential deletion ───────────────────────────────────────────────────────

  test("DELETE /api/webauthn/credentials/{id} returns ok for non-existent credential (idempotent)", async ({
    request,
  }) => {
    const resp = await request.delete(
      `${BASE}/api/webauthn/credentials/nonexistentcredentialid`,
      { headers: { Authorization: `Bearer ${userToken}` } }
    );
    // Handler calls DeletePasskeyCredentialForUser — if it's missing, no error.
    expect(resp.ok()).toBe(true);
    expect((await resp.json()).ok).toBe(true);
  });

  // ── add-device start (requires auth) ─────────────────────────────────────────

  test("POST /api/webauthn/add-device/start without auth returns 401", async ({ request }) => {
    expect(
      (await request.post(`${BASE}/api/webauthn/add-device/start`)).status()
    ).toBe(401);
  });

  test("POST /api/webauthn/add-device/start with valid auth returns a WebAuthn creation options object", async ({
    request,
  }) => {
    const resp = await request.post(`${BASE}/api/webauthn/add-device/start`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    // go-webauthn returns a PublicKeyCredentialCreationOptions wrapper
    expect(body.publicKey).toBeDefined();
    expect(body.publicKey.challenge).toBeTruthy();
    expect(body.publicKey.rp).toBeDefined();
  });

  test("POST /api/webauthn/add-device/finish without nonce cookie returns 400", async ({
    request,
  }) => {
    // No prior add-device/start call in this request context, so no wa_add_nonce cookie.
    const resp = await request.post(`${BASE}/api/webauthn/add-device/finish`, {
      headers: { Authorization: `Bearer ${userToken}` },
      data: {},
    });
    expect(resp.status()).toBe(400);
  });

  // ── login/finish ──────────────────────────────────────────────────────────────

  test("POST /api/webauthn/login/finish without nonce cookie returns 400", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/webauthn/login/finish`, { data: {} });
    expect(resp.status()).toBe(400);
  });
});
