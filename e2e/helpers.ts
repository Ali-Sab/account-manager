import { Page, APIRequestContext } from "@playwright/test";
import * as OTPAuth from "otpauth";
import { execSync } from "child_process";
import path from "path";

/** Base URL for all e2e requests. Set E2E_BASE_URL to point at an external server. */
export const BASE = process.env.E2E_BASE_URL ?? "http://localhost:4001";

/**
 * Redirect URI registered for the gamebacklog-web OAuth client.
 * When E2E_GAMEBACKLOG_REDIRECT_URI is not set and AM_DATA_DIR is available,
 * reads the registered value directly from the DB so tests stay in sync with
 * whatever was seeded at first startup.
 */
export function getGamebacklogRedirectUri(): string {
  if (process.env.E2E_GAMEBACKLOG_REDIRECT_URI) {
    return process.env.E2E_GAMEBACKLOG_REDIRECT_URI;
  }
  if (process.env.AM_DATA_DIR) {
    try {
      return queryDB("SELECT json_extract(redirect_uris, '$[0]') FROM oauth_clients WHERE client_id = 'gamebacklog-web'");
    } catch {
      // DB not accessible — fall through to default.
    }
  }
  return "http://localhost:3000/auth/callback";
}

/**
 * Complete the first-run setup via API (faster than UI for fixtures).
 * Returns { username, password, totpSecret, recoveryCodes }
 *
 * When running against an external server (E2E_BASE_URL set), the server is
 * already configured. Set E2E_ADMIN_USERNAME / E2E_ADMIN_PASSWORD to match
 * the credentials used when the server was first set up.
 */
export async function apiSetup(
  request: APIRequestContext,
  baseURL: string,
  username = process.env.E2E_ADMIN_USERNAME ?? "alice",
  password = process.env.E2E_ADMIN_PASSWORD ?? "password1234"
) {
  // If the server is already configured, skip the setup POST and read the
  // stored TOTP secret directly from the DB — every spec calls this but only
  // the first one (alphabetically) actually performs the setup.
  const statusResp = await request.get(`${baseURL}/api/setup/status`);
  const { configured } = await statusResp.json();
  if (configured) {
    const totpSecret = queryDB(
      `SELECT totp_secret FROM users WHERE username = '${username}'`
    );
    return { username, password, totpSecret, recoveryCodes: [] as string[] };
  }

  const secretResp = await request.get(`${baseURL}/api/setup/secret`);
  const { secret } = await secretResp.json();
  const totpCode = generateTOTP(secret);

  const setupResp = await request.post(`${baseURL}/api/setup`, {
    data: { username, password, totpCode },
  });
  const { recoveryCodes } = await setupResp.json();
  return { username, password, totpSecret: secret, recoveryCodes: recoveryCodes as string[] };
}

/** Generate current TOTP code from a base32 secret string. */
export function generateTOTP(secret: string): string {
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), period: 30 });
  return totp.generate();
}

/**
 * Log in via the API and return tokens. Faster than UI login for fixtures.
 */
export async function apiLogin(
  request: APIRequestContext,
  baseURL: string,
  username: string,
  password: string,
  totpSecret: string
): Promise<{ accessToken: string; csrfToken: string }> {
  const loginResp = await request.post(`${baseURL}/api/auth/login`, {
    data: { username, password },
  });
  const { mfaToken } = await loginResp.json();
  const code = generateTOTP(totpSecret);
  const mfaResp = await request.post(`${baseURL}/api/auth/mfa`, {
    data: { mfaToken, code },
  });
  const { accessToken, csrfToken } = await mfaResp.json();
  return { accessToken, csrfToken };
}

/**
 * Create a user via the admin invite flow.
 * Returns the new user's credentials and TOTP secret.
 */
export async function apiCreateUser(
  request: APIRequestContext,
  baseURL: string,
  adminToken: string,
  username: string,
  password: string
): Promise<{ username: string; password: string; totpSecret: string }> {
  const inviteResp = await request.post(`${baseURL}/api/admin/invite`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  const { token } = await inviteResp.json();

  const secretResp = await request.get(`${baseURL}/api/invite/secret?token=${token}`);
  const { secret } = await secretResp.json();
  const totpCode = generateTOTP(secret);

  await request.post(`${baseURL}/api/invite/accept`, {
    data: { token, username, password, totpCode },
  });

  return { username, password, totpSecret: secret };
}

/**
 * Run a SQL query against the test DB and return the first line of output.
 * Requires sqlite3 CLI (available on macOS by default).
 */
export function queryDB(sql: string): string {
  const dbPath = path.join(process.env.AM_DATA_DIR!, "account-manager.db");
  return execSync(`sqlite3 "${dbPath}" "${sql}"`).toString().trim();
}

/**
 * Read the most recent email verification token for a given username directly from the DB.
 * Works when SMTP is not configured (token is always written regardless of SMTP status).
 */
export function getEmailVerifyToken(username: string): string {
  return queryDB(
    `SELECT token FROM email_verification_tokens WHERE username = '${username}' ORDER BY rowid DESC LIMIT 1`
  );
}

/**
 * Read the plaintext client_secret for an OAuth client directly from the DB.
 * The secret is stored as plaintext only for display purposes (the hash is used for auth).
 */
export function getOAuthClientSecret(clientID: string): string {
  return queryDB(`SELECT client_secret FROM oauth_clients WHERE client_id = '${clientID}'`);
}

/**
 * Perform login via the UI (LoginScreen).
 * Leaves browser on AccountScreen.
 */
export async function uiLogin(
  page: Page,
  baseURL: string,
  username: string,
  password: string,
  totpSecret: string
) {
  await page.goto(baseURL + "/");
  await page.getByLabel(/username/i).fill(username);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /continue/i }).click();

  // MFA step — wait for the 6-digit TOTP input.
  await page.waitForSelector('input[placeholder="6 digits"]', { timeout: 5000 });
  const code = generateTOTP(totpSecret);
  await page.locator('input[placeholder="6 digits"]').fill(code);
  await page.getByRole("button", { name: /verify/i }).click();

  // Wait for account screen.
  await page.waitForSelector("text=Account Settings", { timeout: 5000 });
}
