import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, apiCreateUser, generateTOTP, queryDB, BASE } from "./helpers";

// Read the most recent reset token for a given username directly from the DB.
// When SMTP is configured the email is sent, but the token is still in the DB.
function getResetToken(username: string): string {
  return queryDB(
    `SELECT token FROM password_reset_tokens WHERE username = '${username}' ORDER BY rowid DESC LIMIT 1`
  );
}

test.describe("Password reset flow", () => {
  // Use a dedicated user for all password-reset tests so alice's password is
  // never changed and other spec files stay unaffected on repeated runs.
  let pwrUsername: string;
  let pwrPassword: string;
  let pwrTotpSecret: string;
  let aliceToken: string;

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    const session = await apiLogin(request, BASE, account.username, account.password, account.totpSecret);
    aliceToken = session.accessToken;

    // Create a fresh dedicated user for password-reset tests.
    const pwr = await apiCreateUser(request, BASE, aliceToken, "pwrtest", "pwr-initial-password123");
    pwrUsername = pwr.username;
    pwrPassword = pwr.password;
    pwrTotpSecret = pwr.totpSecret;

    // Set an email address so forgot-password can find the user.
    queryDB(`UPDATE users SET email = 'pwrtest@example.com' WHERE username = '${pwrUsername}'`);
  });

  test.afterAll(async ({ request }) => {
    // Clean up the dedicated user so repeated runs don't fail on "user already exists".
    await request.delete(`${BASE}/api/admin/users/${pwrUsername}`, {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
  });

  test("forgot-password returns 200 for unknown email (no-op, no enumeration)", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/auth/forgot-password`, {
      data: { email: "nobody@example.com" },
    });
    expect(resp.ok()).toBe(true);
  });

  test("forgot-password saves token to DB for known email", async ({ request }) => {
    await request.post(`${BASE}/api/auth/forgot-password`, {
      data: { email: "pwrtest@example.com" },
    });
    const token = getResetToken(pwrUsername);
    expect(token).toBeTruthy();
  });

  test("reset with invalid token returns 401", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/auth/reset-password`, {
      data: { token: "notarealtoken", newPassword: "validpassword123", totpCode: generateTOTP(pwrTotpSecret) },
    });
    expect(resp.status()).toBe(401);
  });

  test("reset with short password returns 400 and token is still usable", async ({ request }) => {
    await request.post(`${BASE}/api/auth/forgot-password`, {
      data: { email: "pwrtest@example.com" },
    });
    const token = getResetToken(pwrUsername);

    // Fail with a short password.
    const badResp = await request.post(`${BASE}/api/auth/reset-password`, {
      data: { token, newPassword: "short", totpCode: generateTOTP(pwrTotpSecret) },
    });
    expect(badResp.status()).toBe(400);

    // Token survives — user can try again with the same link.
    const goodResp = await request.post(`${BASE}/api/auth/reset-password`, {
      data: { token, newPassword: "validnewpassword123", totpCode: generateTOTP(pwrTotpSecret) },
    });
    expect(goodResp.ok()).toBe(true);
    pwrPassword = "validnewpassword123";
  });

  test("reset with wrong TOTP returns 401 and token is still usable", async ({ request }) => {
    await request.post(`${BASE}/api/auth/forgot-password`, {
      data: { email: "pwrtest@example.com" },
    });
    const token = getResetToken(pwrUsername);

    // Fail with bad TOTP.
    const badResp = await request.post(`${BASE}/api/auth/reset-password`, {
      data: { token, newPassword: "validnewpassword456", totpCode: "000000" },
    });
    expect(badResp.status()).toBe(401);

    // Token still usable.
    const goodResp = await request.post(`${BASE}/api/auth/reset-password`, {
      data: { token, newPassword: "validnewpassword456", totpCode: generateTOTP(pwrTotpSecret) },
    });
    expect(goodResp.ok()).toBe(true);
    pwrPassword = "validnewpassword456";
  });

  test("successful reset consumes token and allows login with new password", async ({ request }) => {
    const newPassword = "brandnewpassword789";

    await request.post(`${BASE}/api/auth/forgot-password`, {
      data: { email: "pwrtest@example.com" },
    });
    const token = getResetToken(pwrUsername);

    const resetResp = await request.post(`${BASE}/api/auth/reset-password`, {
      data: { token, newPassword, totpCode: generateTOTP(pwrTotpSecret) },
    });
    expect(resetResp.ok()).toBe(true);
    const { accessToken } = await resetResp.json();
    expect(accessToken).toBeTruthy();

    // Token is consumed — cannot be reused.
    const reuseResp = await request.post(`${BASE}/api/auth/reset-password`, {
      data: { token, newPassword: "anotherpassword000", totpCode: generateTOTP(pwrTotpSecret) },
    });
    expect(reuseResp.status()).toBe(401);

    // Can log in with new password.
    const { accessToken: newToken } = await apiLogin(request, BASE, pwrUsername, newPassword, pwrTotpSecret);
    expect(newToken).toBeTruthy();
    pwrPassword = newPassword;
  });
});
