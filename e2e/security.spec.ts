// Security enforcement: unauthenticated access, authorization levels, CSRF,
// and MFA token edge cases.
import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, apiCreateUser, generateTOTP, BASE } from "./helpers";

test.describe("Security enforcement", () => {
  let adminToken: string;
  let adminCsrf: string;
  let totpSecret: string;

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    totpSecret = account.totpSecret;
    const session = await apiLogin(
      request, BASE, account.username, account.password, account.totpSecret
    );
    adminToken = session.accessToken;
    adminCsrf = session.csrfToken;
  });

  // ── Unauthenticated access to requireAuth routes ──────────────────────────────

  test("GET /api/auth/me without token returns 401", async ({ request }) => {
    expect((await request.get(`${BASE}/api/auth/me`)).status()).toBe(401);
  });

  test("GET /api/auth/me with garbage token returns 401", async ({ request }) => {
    expect(
      (await request.get(`${BASE}/api/auth/me`, { headers: { Authorization: "Bearer garbage" } })).status()
    ).toBe(401);
  });

  test("POST /api/auth/change-password without token returns 401", async ({ request }) => {
    expect(
      (
        await request.post(`${BASE}/api/auth/change-password`, {
          data: { currentPassword: "x", newPassword: "y" },
        })
      ).status()
    ).toBe(401);
  });

  test("DELETE /api/auth/account without token returns 401", async ({ request }) => {
    expect(
      (await request.delete(`${BASE}/api/auth/account`, { data: { password: "x" } })).status()
    ).toBe(401);
  });

  test("POST /api/auth/recovery-codes/regenerate without token returns 401", async ({
    request,
  }) => {
    expect(
      (await request.post(`${BASE}/api/auth/recovery-codes/regenerate`)).status()
    ).toBe(401);
  });

  test("GET /api/auth/recovery-codes/count without token returns 401", async ({ request }) => {
    expect(
      (await request.get(`${BASE}/api/auth/recovery-codes/count`)).status()
    ).toBe(401);
  });

  test("PUT /api/auth/email without token returns 401", async ({ request }) => {
    expect(
      (await request.put(`${BASE}/api/auth/email`, { data: { email: "x@x.com" } })).status()
    ).toBe(401);
  });

  test("GET /api/auth/email/pending without token returns 401", async ({ request }) => {
    expect((await request.get(`${BASE}/api/auth/email/pending`)).status()).toBe(401);
  });

  test("GET /api/webauthn/credentials without token returns 401", async ({ request }) => {
    expect((await request.get(`${BASE}/api/webauthn/credentials`)).status()).toBe(401);
  });

  test("DELETE /api/webauthn/credentials/x without token returns 401", async ({ request }) => {
    expect((await request.delete(`${BASE}/api/webauthn/credentials/x`)).status()).toBe(401);
  });

  // ── Admin-only routes ─────────────────────────────────────────────────────────

  test("GET /api/admin/users without token returns 401", async ({ request }) => {
    expect((await request.get(`${BASE}/api/admin/users`)).status()).toBe(401);
  });

  test("DELETE /api/admin/users/alice without token returns 401", async ({ request }) => {
    expect((await request.delete(`${BASE}/api/admin/users/alice`)).status()).toBe(401);
  });

  test("POST /api/admin/invite without token returns 401", async ({ request }) => {
    expect((await request.post(`${BASE}/api/admin/invite`)).status()).toBe(401);
  });

  test("GET /api/admin/users as non-admin returns 403", async ({ request }) => {
    const user = await apiCreateUser(request, BASE, adminToken, "sectest1", "sectestpass123");
    const session = await apiLogin(request, BASE, "sectest1", "sectestpass123", user.totpSecret);

    expect(
      (await request.get(`${BASE}/api/admin/users`, {
        headers: { Authorization: `Bearer ${session.accessToken}` },
      })).status()
    ).toBe(403);

    await request.delete(`${BASE}/api/admin/users/sectest1`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });

  test("POST /api/admin/invite as non-admin returns 403", async ({ request }) => {
    const user = await apiCreateUser(request, BASE, adminToken, "sectest2", "sectestpass123");
    const session = await apiLogin(request, BASE, "sectest2", "sectestpass123", user.totpSecret);

    expect(
      (await request.post(`${BASE}/api/admin/invite`, {
        headers: { Authorization: `Bearer ${session.accessToken}` },
      })).status()
    ).toBe(403);

    await request.delete(`${BASE}/api/admin/users/sectest2`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });

  // ── CSRF protection ───────────────────────────────────────────────────────────

  test("POST /api/auth/refresh without CSRF header returns 403", async ({ request }) => {
    // Log in so the refreshToken cookie is set.
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    const { mfaToken } = await loginResp.json();
    await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code: generateTOTP(totpSecret) },
    });

    // Try to refresh with no CSRF token — should be rejected.
    const refreshResp = await request.post(`${BASE}/api/auth/refresh`);
    expect(refreshResp.status()).toBe(403);
  });

  test("POST /api/auth/refresh with wrong CSRF token returns 403", async ({ request }) => {
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    const { mfaToken } = await loginResp.json();
    await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code: generateTOTP(totpSecret) },
    });

    const refreshResp = await request.post(`${BASE}/api/auth/refresh`, {
      headers: { "X-CSRF-Token": "totallywrong" },
    });
    expect(refreshResp.status()).toBe(403);
  });

  // ── MFA token edge cases ──────────────────────────────────────────────────────

  test("POST /api/auth/mfa with garbage mfaToken returns 401", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken: "garbage.token.value", code: "000000" },
    });
    expect(resp.status()).toBe(401);
  });

  test("POST /api/auth/mfa with valid mfaToken but wrong TOTP returns 401", async ({
    request,
  }) => {
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    const { mfaToken } = await loginResp.json();

    const resp = await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code: "000000" },
    });
    expect(resp.status()).toBe(401);
  });

  test("POST /api/auth/recovery with garbage mfaToken returns 401", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/auth/recovery`, {
      data: { mfaToken: "garbage.token.value", code: "xxxx-xxxx-xx" },
    });
    expect(resp.status()).toBe(401);
  });

  // ── Username enumeration protection ──────────────────────────────────────────

  test("login with non-existent username returns 401 (same as wrong password)", async ({
    request,
  }) => {
    const resp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "doesnotexist", password: "password1234" },
    });
    expect(resp.status()).toBe(401);
  });

  test("POST /api/auth/forgot-password with unknown email returns 200 (no enumeration)", async ({
    request,
  }) => {
    const resp = await request.post(`${BASE}/api/auth/forgot-password`, {
      data: { email: "nobody@nowhere.com" },
    });
    expect(resp.ok()).toBe(true); // always 200 to prevent enumeration
  });

  // ── Bearer token format ───────────────────────────────────────────────────────

  test("token without Bearer prefix returns 401", async ({ request }) => {
    expect(
      (await request.get(`${BASE}/api/auth/me`, { headers: { Authorization: adminToken } })).status()
    ).toBe(401);
  });

  test("empty Authorization header returns 401", async ({ request }) => {
    expect(
      (await request.get(`${BASE}/api/auth/me`, { headers: { Authorization: "" } })).status()
    ).toBe(401);
  });
});
