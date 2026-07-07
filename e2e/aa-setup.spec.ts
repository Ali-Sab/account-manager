// Runs FIRST in the test suite (alphabetically before account-*.spec.ts) so that
// validation tests hit an unconfigured server and the wizard test is what actually
// seeds alice into a fresh DB.  All other spec files call apiSetup() which is a
// no-op when the server is already configured.
import { test, expect } from "@playwright/test";
import * as OTPAuth from "otpauth";
import { generateTOTP, BASE } from "./helpers";

test.describe("First-run setup", () => {
  test("status shows unconfigured on fresh server", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/setup/status`);
    expect(resp.ok()).toBe(true);
    const { configured, hasPasskeys } = await resp.json();
    expect(configured).toBe(false);
    expect(hasPasskeys).toBe(false);
  });

  test("secret endpoint returns TOTP QR and formatted secret", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/setup/secret`);
    expect(resp.ok()).toBe(true);
    const { secret, qrDataUrl, formatted } = await resp.json();
    expect(secret).toBeTruthy();
    expect(qrDataUrl).toMatch(/^data:image\/png;base64,/);
    // formatted groups the base32 secret into 4-char blocks separated by spaces
    expect(formatted).toMatch(/^[A-Z2-7]{4}( [A-Z2-7]{4})*$/i);
  });

  // ── Validation tests ────────────────────────────────────────────────────────
  // These send bad data that the server rejects before creating any user,
  // so the server remains unconfigured.

  test("setup rejects password shorter than 12 chars", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "alice", password: "short", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
    const { error } = await resp.json();
    expect(error).toMatch(/12/);
  });

  test("setup rejects username with spaces", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "ali ce", password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("setup rejects username with special characters", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "alice!", password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("setup rejects username over 32 chars", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "a".repeat(33), password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("setup rejects empty username", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "", password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
  });

  test("setup rejects invalid email format", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: {
        username: "alice",
        password: "validpassword123",
        email: "notanemail",
        totpCode: "000000",
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("setup rejects invalid email missing TLD", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: {
        username: "alice",
        password: "validpassword123",
        email: "user@nodot",
        totpCode: "000000",
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("setup rejects wrong TOTP code", async ({ request }) => {
    // A valid pending-setup row exists from the "secret endpoint" test above.
    // We submit a clearly invalid 6-digit code.
    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "alice", password: "validpassword123", totpCode: "000000" },
    });
    expect(resp.status()).toBe(400);
    const { error } = await resp.json();
    // Could be "Setup session expired" (if first call already used up the pending row)
    // or "Invalid TOTP code" — either way not a successful setup.
    expect(error).toBeTruthy();
  });

  // ── Wizard happy path ────────────────────────────────────────────────────────

  test("setup wizard completes: creates admin user and returns recovery codes", async ({
    request,
  }) => {
    // Get a fresh pending-setup row.
    const secretResp = await request.get(`${BASE}/api/setup/secret`);
    expect(secretResp.ok()).toBe(true);
    const { secret } = await secretResp.json();
    const totpCode = generateTOTP(secret);

    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "alice", password: "password1234", totpCode },
    });
    expect(resp.ok()).toBe(true);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(Array.isArray(body.recoveryCodes)).toBe(true);
    expect(body.recoveryCodes).toHaveLength(8);
    // Each code has the xxxx-xxxx-xx format documented in CLAUDE.md.
    for (const code of body.recoveryCodes) {
      expect(code).toMatch(/^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{2}$/);
    }
  });

  test("status shows configured after wizard", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/setup/status`);
    const { configured } = await resp.json();
    expect(configured).toBe(true);
  });

  // ── Post-setup lockdown ──────────────────────────────────────────────────────

  test("secret endpoint returns 403 when already configured", async ({ request }) => {
    const resp = await request.get(`${BASE}/api/setup/secret`);
    expect(resp.status()).toBe(403);
  });

  test("setup endpoint returns 403 when already configured", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/setup`, {
      data: { username: "other", password: "password1234", totpCode: "000000" },
    });
    expect(resp.status()).toBe(403);
  });

  test("webauthn register/start returns 403 when already configured", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/webauthn/register/start`, {
      data: { username: "other", password: "password1234" },
    });
    expect(resp.status()).toBe(403);
  });

  test("webauthn register/finish returns 403 when already configured", async ({ request }) => {
    const resp = await request.post(`${BASE}/api/webauthn/register/finish`, {
      data: {},
    });
    expect(resp.status()).toBe(403);
  });
});
