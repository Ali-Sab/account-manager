// Invite flow: admin creates invite → user accepts → new account is usable.
// Also covers all validation edge cases on /api/invite/accept.
import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, generateTOTP, BASE } from "./helpers";

test.describe("Invite flow", () => {
  let adminToken: string;
  let adminCsrf: string;

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    const session = await apiLogin(
      request, BASE, account.username, account.password, account.totpSecret
    );
    adminToken = session.accessToken;
    adminCsrf = session.csrfToken;
  });

  // ── Admin invite creation ─────────────────────────────────────────────────────

  test("non-admin cannot create invite", async ({ request }) => {
    // Create a non-admin user first so we have a non-admin token.
    const inviteResp = await request.post(`${BASE}/api/admin/invite`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const { token } = await inviteResp.json();

    // Accept invite as nonadmin1.
    const secretResp = await request.get(`${BASE}/api/invite/secret?token=${token}`);
    const { secret } = await secretResp.json();
    await request.post(`${BASE}/api/invite/accept`, {
      data: { token, username: "nonadmin1", password: "nonadmin1pass123", totpCode: generateTOTP(secret) },
    });

    const nonadminSession = await apiLogin(request, BASE, "nonadmin1", "nonadmin1pass123", secret);

    const resp = await request.post(`${BASE}/api/admin/invite`, {
      headers: { Authorization: `Bearer ${nonadminSession.accessToken}` },
    });
    expect(resp.status()).toBe(403);

    // Clean up.
    await request.delete(`${BASE}/api/admin/users/nonadmin1`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });

  test("admin creates invite — returns token and invite URL", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/admin/invite`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.token).toBeTruthy();
    expect(body.url).toContain("/accounts/");
    expect(body.url).toContain(body.token);
  });

  // ── Invite secret endpoint ────────────────────────────────────────────────────

  test("GET /api/invite/secret with invalid token returns 400", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/invite/secret?token=notarealtoken`);
    expect(resp.status()).toBe(400);
  });

  test("GET /api/invite/secret with missing token returns 400", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/invite/secret`);
    expect(resp.status()).toBe(400);
  });

  test("GET /api/invite/secret with valid token returns TOTP QR and secret", async ({
    request,
  }) => {
    const inviteResp = await request.post(`${BASE}/api/admin/invite`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const { token } = await inviteResp.json();

    const resp = await request.get(`${BASE}/api/invite/secret?token=${token}`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.secret).toBeTruthy();
    expect(body.qrDataUrl).toMatch(/^data:image\/png;base64,/);
    expect(body.formatted).toBeTruthy();
  });

  // ── Accept invite — validation ────────────────────────────────────────────────

  async function freshInviteToken(request: any): Promise<string> {
    const r = await request.post(`${BASE}/api/admin/invite`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    return (await r.json()).token;
  }

  async function inviteSecret(request: any, token: string): Promise<string> {
    const r = await request.get(`${BASE}/api/invite/secret?token=${token}`);
    return (await r.json()).secret;
  }

  test("accept: invalid token returns 400", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: { token: "bogustoken", username: "newuser", password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("accept: password shorter than 12 chars returns 400", async ({ request }) => {
    const token = await freshInviteToken(request);
    await inviteSecret(request, token); // must fetch secret before accepting

    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: { token, username: "newuser", password: "short", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).error).toMatch(/12/);
  });

  test("accept: username with special chars returns 400", async ({ request }) => {
    const token = await freshInviteToken(request);
    await inviteSecret(request, token);

    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: { token, username: "bad user!", password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("accept: invalid email format returns 400", async ({ request }) => {
    const token = await freshInviteToken(request);
    await inviteSecret(request, token);

    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: { token, username: "newuser", password: "validpassword123", email: "bademail", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("accept: wrong TOTP code returns 400", async ({ request }) => {
    const token = await freshInviteToken(request);
    await inviteSecret(request, token);

    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: { token, username: "newuser", password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("accept: duplicate username returns 400", async ({ request }) => {
    const token = await freshInviteToken(request);
    const secret = await inviteSecret(request, token);

    // "alice" is the admin username created in setup — always a duplicate.
    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: { token, username: "alice", password: "validpassword123", totpCode: generateTOTP(secret) },
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).error).toMatch(/taken/i);
  });

  // ── Accept invite — happy path ────────────────────────────────────────────────

  test("accept: happy path creates non-admin user and returns recovery codes", async ({
    request,
  }) => {
    const token = await freshInviteToken(request);
    const secret = await inviteSecret(request, token);

    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: {
        token,
        username: "invitee1",
        password: "inviteepass123",
        totpCode: generateTOTP(secret),
      },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.recoveryCodes).toHaveLength(8);

    // Verify the new user can log in.
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "invitee1", password: "inviteepass123" },
    });
    expect(loginResp.ok()).toBe(true);
    const { mfaToken } = await loginResp.json();

    const mfaResp = await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code: generateTOTP(secret) },
    });
    expect(mfaResp.ok()).toBe(true);
    const { accessToken } = await mfaResp.json();
    expect(accessToken).toBeTruthy();

    // Invited users are not admins.
    const meResp = await request.get(`${BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect((await meResp.json()).isAdmin).toBe(false);

    // Clean up.
    await request.delete(`${BASE}/api/admin/users/invitee1`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });

  test("invite token is consumed after accept — reuse returns 400", async ({ request }) => {
    const token = await freshInviteToken(request);
    const secret = await inviteSecret(request, token);

    // First accept.
    await request.post(`${BASE}/api/invite/accept`, {
      data: {
        token,
        username: "invitee2",
        password: "inviteepass123",
        totpCode: generateTOTP(secret),
      },
    });

    // Second accept with same token.
    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: {
        token,
        username: "invitee3",
        password: "inviteepass123",
        totpCode: generateTOTP(secret),
      },
    });
    expect(resp.status()).toBe(400);

    // Clean up.
    await request.delete(`${BASE}/api/admin/users/invitee2`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });

  test("invite with optional email sets pending verification on accept", async ({ request }) => {
    const token = await freshInviteToken(request);
    const secret = await inviteSecret(request, token);

    const resp = await request.post(`${BASE}/api/invite/accept`, {
      data: {
        token,
        username: "invitee4",
        password: "inviteepass123",
        email: "invitee4@example.com",
        totpCode: generateTOTP(secret),
      },
    });
    expect(resp.ok()).toBe(true);
    expect((await resp.json()).emailPending).toBe(true);

    // Clean up.
    await request.delete(`${BASE}/api/admin/users/invitee4`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });
});
