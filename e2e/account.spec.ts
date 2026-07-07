import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, apiCreateUser, generateTOTP, BASE } from "./helpers";

test.describe("Account management", () => {
  let accessToken: string;
  let csrfToken: string;
  let totpSecret: string;
  const username = "alice";
  const password = "password1234";

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    totpSecret = account.totpSecret;

    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: account.username, password: account.password },
    });
    const { mfaToken } = await loginResp.json();
    const code = generateTOTP(totpSecret);
    const mfaResp = await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code },
    });
    const body = await mfaResp.json();
    accessToken = body.accessToken;
    csrfToken = body.csrfToken;
  });

  // ── /api/auth/me ─────────────────────────────────────────────────────────────

  test("GET /api/auth/me returns username, email, and isAdmin", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.username).toBe(username);
    expect(body.isAdmin).toBe(true);
    // email is optional — just verify the field is present
    expect("email" in body).toBe(true);
  });

  // ── Recovery codes ────────────────────────────────────────────────────────────

  test("recovery code count returns 8 on fresh account", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/auth/recovery-codes/count`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(resp.ok()).toBe(true);
    const { remaining } = await resp.json();
    expect(remaining).toBe(8);
  });

  test("regenerate recovery codes returns 8 new codes", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/auth/recovery-codes/regenerate`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(resp.ok()).toBe(true);
    const { recoveryCodes } = await resp.json();
    expect(recoveryCodes).toHaveLength(8);
    expect(recoveryCodes[0]).toMatch(/^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{2}$/);
  });

  test("count decrements after a recovery code is consumed", async ({ request }) => {
    // Regen so we have fresh plaintext codes.
    const regenResp = await request.post(`${BASE}/api/auth/recovery-codes/regenerate`, {
      headers: { Authorization: `Bearer ${accessToken}`, "X-CSRF-Token": csrfToken },
    });
    const { recoveryCodes } = await regenResp.json();

    // Use one code via the recovery login flow.
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username, password },
    });
    const { mfaToken } = await loginResp.json();
    const recoveryResp = await request.post(`${BASE}/api/auth/recovery`, {
      data: { mfaToken, code: recoveryCodes[0] },
    });
    expect(recoveryResp.ok()).toBe(true);
    const { remaining } = await recoveryResp.json();
    expect(remaining).toBe(7);

    // Count endpoint agrees.
    const countResp = await request.get(`${BASE}/api/auth/recovery-codes/count`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect((await countResp.json()).remaining).toBe(7);
  });

  // ── Change password ───────────────────────────────────────────────────────────

  test("change password: wrong current password returns 401", async ({ request }) => {
    const bad = await request.post(`${BASE}/api/auth/change-password`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      data: { currentPassword: "wrongpass", newPassword: "newpassword456" },
    });
    expect(bad.status()).toBe(401);
  });

  test("change password: new password too short returns 400", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/auth/change-password`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      data: { currentPassword: password, newPassword: "short" },
    });
    expect(resp.status()).toBe(400);
    expect((await resp.json()).error).toMatch(/12/);
  });

  test("change password: success invalidates old sessions and returns recovery codes", async ({
    request,
  }) => {
    // Create a throwaway user (eve) so alice's password stays intact for other tests.
    const session = await apiLogin(request, BASE, username, password, totpSecret);
    const eve = await apiCreateUser(request, BASE, session.accessToken, "eve", "evepassword123");
    const eveSession = await apiLogin(request, BASE, "eve", "evepassword123", eve.totpSecret);

    const newPassword = "evenewpassword789";
    const changeResp = await request.post(`${BASE}/api/auth/change-password`, {
      headers: { Authorization: `Bearer ${eveSession.accessToken}` },
      data: { currentPassword: "evepassword123", newPassword },
    });
    expect(changeResp.ok()).toBe(true);
    const changeBody = await changeResp.json();
    expect(changeBody.ok).toBe(true);
    // Change password regenerates recovery codes.
    expect(changeBody.recoveryCodes).toHaveLength(8);

    // Old session's refresh token is revoked — refresh must fail.
    const refreshResp = await request.post(`${BASE}/api/auth/refresh`, {
      headers: { "X-CSRF-Token": eveSession.csrfToken },
    });
    expect(refreshResp.status()).toBe(401);

    // Eve can log in with the new password.
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "eve", password: newPassword },
    });
    expect(loginResp.ok()).toBe(true);

    // Eve cannot log in with the old password.
    const oldLoginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "eve", password: "evepassword123" },
    });
    expect(oldLoginResp.status()).toBe(401);

    // Clean up eve.
    await request.delete(`${BASE}/api/admin/users/eve`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  });

  // ── Admin endpoints ───────────────────────────────────────────────────────────

  test("GET /api/admin/users lists all users including alice", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/admin/users`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(resp.ok()).toBe(true);
    const users = await resp.json();
    expect(Array.isArray(users)).toBe(true);
    const alice = users.find((u: { username: string }) => u.username === username);
    expect(alice).toBeDefined();
    expect(alice.isAdmin).toBe(true);
    expect("email" in alice).toBe(true);
    expect(typeof alice.createdAt).toBe("number");
  });

  test("GET /api/admin/users as non-admin returns 403", async ({ request }) => {
    // Create a non-admin user.
    const session = await apiLogin(request, BASE, username, password, totpSecret);
    const frank = await apiCreateUser(request, BASE, session.accessToken, "frank", "frankpassword123");
    const frankSession = await apiLogin(request, BASE, "frank", "frankpassword123", frank.totpSecret);

    const resp = await request.get(`${BASE}/api/admin/users`, {
      headers: { Authorization: `Bearer ${frankSession.accessToken}` },
    });
    expect(resp.status()).toBe(403);

    // Clean up.
    await request.delete(`${BASE}/api/admin/users/frank`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  });
});
