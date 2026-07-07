import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, generateTOTP, BASE } from "./helpers";

test.describe("Login flow", () => {
  let totpSecret: string;
  let recoveryCodes: string[];

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    totpSecret = account.totpSecret;
    recoveryCodes = account.recoveryCodes ?? [];
  });

  test("login with correct credentials returns access token", async ({ request }) => {
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    expect(loginResp.ok()).toBe(true);
    const { mfaToken } = await loginResp.json();
    expect(mfaToken).toBeTruthy();

    const code = generateTOTP(totpSecret);
    const mfaResp = await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code },
    });
    expect(mfaResp.ok()).toBe(true);
    const { accessToken, csrfToken } = await mfaResp.json();
    expect(accessToken).toBeTruthy();
    expect(csrfToken).toBeTruthy();
  });

  test("wrong password returns 401", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "wrongpass" },
    });
    expect(resp.status()).toBe(401);
  });

  test("refresh with valid cookie returns new access token", async ({ request }) => {
    // Full login to get refresh cookie.
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    const { mfaToken } = await loginResp.json();
    const code = generateTOTP(totpSecret);
    const mfaResp = await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code },
    });
    const { csrfToken } = await mfaResp.json();

    // Refresh.
    const refreshResp = await request.post(`${BASE}/api/auth/refresh`, {
      headers: { "X-CSRF-Token": csrfToken },
    });
    expect(refreshResp.ok()).toBe(true);
    const { accessToken } = await refreshResp.json();
    expect(accessToken).toBeTruthy();
  });

  test("recovery code login works and code is consumed", async ({ request }) => {
    // Regenerate recovery codes so we have plaintext codes regardless of whether
    // this server was freshly set up or already configured when the suite started.
    const session = await apiLogin(request, BASE, "alice", "password1234", totpSecret);
    const regenResp = await request.post(`${BASE}/api/auth/recovery-codes/regenerate`, {
      headers: { Authorization: `Bearer ${session.accessToken}`, "X-CSRF-Token": session.csrfToken },
    });
    expect(regenResp.ok()).toBe(true);
    const { recoveryCodes: freshCodes } = await regenResp.json();
    expect(freshCodes).toHaveLength(8);

    // Use a recovery code instead of TOTP.
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    const { mfaToken } = await loginResp.json();
    const recoveryResp = await request.post(`${BASE}/api/auth/recovery`, {
      data: { mfaToken, code: freshCodes[0] },
    });
    expect(recoveryResp.ok()).toBe(true);
    const { accessToken } = await recoveryResp.json();
    expect(accessToken).toBeTruthy();

    // Same code is now consumed — reuse should fail.
    const loginResp2 = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    const { mfaToken: mfaToken2 } = await loginResp2.json();
    const reuseResp = await request.post(`${BASE}/api/auth/recovery`, {
      data: { mfaToken: mfaToken2, code: freshCodes[0] },
    });
    expect(reuseResp.status()).toBe(401);
  });

  test("logout clears cookie", async ({ request }) => {
    const loginResp = await request.post(`${BASE}/api/auth/login`, {
      data: { username: "alice", password: "password1234" },
    });
    const { mfaToken } = await loginResp.json();
    const code = generateTOTP(totpSecret);
    const mfaResp = await request.post(`${BASE}/api/auth/mfa`, {
      data: { mfaToken, code },
    });
    const { csrfToken } = await mfaResp.json();

    const logoutResp = await request.post(`${BASE}/api/auth/logout`, {
      headers: { "X-CSRF-Token": csrfToken },
    });
    expect(logoutResp.ok()).toBe(true);

    // Refresh after logout should fail.
    const refreshResp = await request.post(`${BASE}/api/auth/refresh`, {
      headers: { "X-CSRF-Token": csrfToken },
    });
    expect(refreshResp.status()).toBe(401);
  });
});
