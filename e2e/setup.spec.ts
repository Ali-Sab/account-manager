import { test, expect } from "@playwright/test";
import * as OTPAuth from "otpauth";
import { BASE } from "./helpers";

test("first-run setup wizard completes successfully", async ({ page, request }) => {
  // Verify unconfigured state. Skip if another spec already ran setup
  // (setup.spec.ts must run on a fresh server to test the wizard end-to-end).
  const statusResp = await request.get(`${BASE}/api/setup/status`);
  const status = await statusResp.json();
  test.skip(status.configured === true, "Server already configured — run this spec in isolation on a fresh server");
  expect(status.configured).toBe(false);

  // Get TOTP secret via API.
  const secretResp = await request.get(`${BASE}/api/setup/secret`);
  expect(secretResp.ok()).toBe(true);
  const { secret, qrDataUrl } = await secretResp.json();
  expect(secret).toBeTruthy();
  expect(qrDataUrl).toMatch(/^data:image\/png/);

  // Generate a valid TOTP code.
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), period: 30 });
  const code = totp.generate();

  // Submit setup.
  const setupResp = await request.post(`${BASE}/api/setup`, {
    data: { username: "alice", password: "password1234", totpCode: code },
  });
  expect(setupResp.ok()).toBe(true);
  const setupBody = await setupResp.json();
  expect(setupBody.ok).toBe(true);
  expect(Array.isArray(setupBody.recoveryCodes)).toBe(true);
  expect(setupBody.recoveryCodes).toHaveLength(8);

  // Verify configured state.
  const status2 = await (await request.get(`${BASE}/api/setup/status`)).json();
  expect(status2.configured).toBe(true);
});
