// Email update / verify / cancel flow.
// SMTP is not configured in the test server, so the verification token is written
// to the DB but no email is actually sent.  We read it directly via queryDB.
import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, apiCreateUser, queryDB, getEmailVerifyToken, BASE } from "./helpers";

test.describe("Email verification flow", () => {
  let adminToken: string;
  let userToken: string;
  let userTotpSecret: string;

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    const adminSession = await apiLogin(
      request, BASE, account.username, account.password, account.totpSecret
    );
    adminToken = adminSession.accessToken;

    // Create a dedicated user so alice's state is untouched.
    const emailUser = await apiCreateUser(request, BASE, adminToken, "emailtester", "emailtester123");
    userTotpSecret = emailUser.totpSecret;
    const userSession = await apiLogin(request, BASE, "emailtester", "emailtester123", userTotpSecret);
    userToken = userSession.accessToken;
  });

  test.afterAll(async ({ request }) => {
    await request.delete(`${BASE}/api/admin/users/emailtester`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
  });

  // ── Validation ────────────────────────────────────────────────────────────────

  test("PUT /api/auth/email with invalid format returns 400", async ({ request }) => {
    const resp = await request.put(`${BASE}/api/auth/email`, {
      headers: { Authorization: `Bearer ${userToken}` },
      data: { email: "notanemail" },
    });
    expect(resp.status()).toBe(400);
  });

  test("PUT /api/auth/email with missing TLD returns 400", async ({ request }) => {
    const resp = await request.put(`${BASE}/api/auth/email`, {
      headers: { Authorization: `Bearer ${userToken}` },
      data: { email: "user@nodot" },
    });
    expect(resp.status()).toBe(400);
  });

  // ── Set email (starts pending verification) ───────────────────────────────────

  test("PUT /api/auth/email with valid address returns pending:true", async ({ request }) => {
    const resp = await request.put(`${BASE}/api/auth/email`, {
      headers: { Authorization: `Bearer ${userToken}` },
      data: { email: "emailtester@example.com" },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.pending).toBe(true);
    expect(body.email).toBe("emailtester@example.com");
  });

  test("GET /api/auth/email/pending returns the waiting email", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/auth/email/pending`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.email).toBe("emailtester@example.com");
  });

  // ── Verify token ──────────────────────────────────────────────────────────────

  test("GET /api/auth/email/verify with invalid token returns 401", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/auth/email/verify?token=notarealtoken`);
    expect(resp.status()).toBe(401);
  });

  test("GET /api/auth/email/verify with valid token updates email on account", async ({
    request,
  }) => {
    const token = getEmailVerifyToken("emailtester");
    expect(token).toBeTruthy();

    const resp = await request.get(`${BASE}/api/auth/email/verify?token=${token}`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.email).toBe("emailtester@example.com");
  });

  test("GET /api/auth/email/verify token is consumed — reuse returns 401", async ({
    request,
  }) => {
    // Set a new pending email so there's a fresh token to consume first.
    await request.put(`${BASE}/api/auth/email`, {
      headers: { Authorization: `Bearer ${userToken}` },
      data: { email: "emailtester2@example.com" },
    });
    const token = getEmailVerifyToken("emailtester");

    // First use: succeeds.
    const first = await request.get(`${BASE}/api/auth/email/verify?token=${token}`);
    expect(first.ok()).toBe(true);

    // Second use: token already consumed.
    const second = await request.get(`${BASE}/api/auth/email/verify?token=${token}`);
    expect(second.status()).toBe(401);
  });

  test("GET /api/auth/me reflects verified email", async ({ request }) => {
    // After the verification tests above, the email should be emailtester2@example.com.
    const resp = await request.get(`${BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    expect(resp.ok()).toBe(true);
    const { email } = await resp.json();
    expect(email).toBe("emailtester2@example.com");
  });

  // ── Cancel pending verification ───────────────────────────────────────────────

  test("DELETE /api/auth/email/pending cancels the pending verification", async ({ request }) => {
    // Each test gets a fresh request context (no cookies from beforeAll).
    // GET /api/auth/csrf sets the csrf_token cookie and returns the signed token.
    const csrfResp = await request.get(`${BASE}/api/auth/csrf`);
    const { csrfToken: freshCsrf } = await csrfResp.json();

    // Start a new pending verification.
    await request.put(`${BASE}/api/auth/email`, {
      headers: { Authorization: `Bearer ${userToken}` },
      data: { email: "cancelled@example.com" },
    });

    // Confirm it's pending.
    const pendingResp = await request.get(`${BASE}/api/auth/email/pending`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    expect((await pendingResp.json()).email).toBe("cancelled@example.com");

    // Cancel it — CSRF-protected endpoint.
    const cancelResp = await request.delete(`${BASE}/api/auth/email/pending`, {
      headers: { Authorization: `Bearer ${userToken}`, "X-CSRF-Token": freshCsrf },
    });
    expect(cancelResp.ok()).toBe(true);

    // Pending is gone.
    const afterResp = await request.get(`${BASE}/api/auth/email/pending`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    const afterBody = await afterResp.json();
    expect(afterBody.email).toBeUndefined();

    // The token that was queued is now invalid.
    const savedToken = queryDB(
      `SELECT token FROM email_verification_tokens WHERE username = 'emailtester' ORDER BY rowid DESC LIMIT 1`
    );
    if (savedToken) {
      const verifyResp = await request.get(`${BASE}/api/auth/email/verify?token=${savedToken}`);
      expect(verifyResp.status()).toBe(401);
    }
  });

  // ── Remove email ──────────────────────────────────────────────────────────────

  test("PUT /api/auth/email with empty string removes email without verification", async ({
    request,
  }) => {
    const resp = await request.put(`${BASE}/api/auth/email`, {
      headers: { Authorization: `Bearer ${userToken}` },
      data: { email: "" },
    });
    expect(resp.ok()).toBe(true);
    expect((await resp.json()).ok).toBe(true);

    // Email is cleared immediately — no pending step.
    const meResp = await request.get(`${BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${userToken}` },
    });
    expect((await meResp.json()).email).toBe("");
  });

  test("GET /api/auth/email/verify with missing token returns 400", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/auth/email/verify`);
    expect(resp.status()).toBe(400);
  });
});
