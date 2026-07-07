import { test, expect } from "@playwright/test";
import { apiSetup, apiLogin, apiCreateUser, BASE } from "./helpers";

test.describe("Account deletion", () => {
  let aliceTotpSecret: string;
  let aliceToken: string;

  test.beforeAll(async ({ request }) => {
    const account = await apiSetup(request, BASE);
    aliceTotpSecret = account.totpSecret;
    const session = await apiLogin(request, BASE, "alice", "password1234", aliceTotpSecret);
    aliceToken = session.accessToken;
  });

  test.describe("Self-service (DELETE /api/auth/account)", () => {
    test("wrong password returns 401 and account is not deleted", async ({ request }) => {
      const resp = await request.delete(`${BASE}/api/auth/account`, {
        headers: { Authorization: `Bearer ${aliceToken}` },
        data: { password: "wrongpassword" },
      });
      expect(resp.status()).toBe(401);

      // Alice can still log in.
      const loginResp = await request.post(`${BASE}/api/auth/login`, {
        data: { username: "alice", password: "password1234" },
      });
      expect(loginResp.ok()).toBe(true);
    });

    test("last admin cannot self-delete via DELETE /api/auth/account", async ({ request }) => {
      const resp = await request.delete(`${BASE}/api/auth/account`, {
        headers: { Authorization: `Bearer ${aliceToken}` },
        data: { password: "password1234" },
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.error).toMatch(/only admin/i);

      // Alice still exists.
      const loginResp = await request.post(`${BASE}/api/auth/login`, {
        data: { username: "alice", password: "password1234" },
      });
      expect(loginResp.ok()).toBe(true);
    });

    test("correct password deletes account and invalidates session", async ({ request }) => {
      // Create bob via invite so we don't lose alice for other tests.
      const bob = await apiCreateUser(request, BASE, aliceToken, "bob", "bobpassword123");
      const bobSession = await apiLogin(request, BASE, "bob", "bobpassword123", bob.totpSecret);

      const resp = await request.delete(`${BASE}/api/auth/account`, {
        headers: { Authorization: `Bearer ${bobSession.accessToken}` },
        data: { password: "bobpassword123" },
      });
      expect(resp.ok()).toBe(true);

      // Refresh cookie should be cleared — refresh must fail.
      const refreshResp = await request.post(`${BASE}/api/auth/refresh`, {
        headers: { "X-CSRF-Token": bobSession.csrfToken },
      });
      expect(refreshResp.status()).toBe(401);

      // Bob can no longer log in.
      const loginResp = await request.post(`${BASE}/api/auth/login`, {
        data: { username: "bob", password: "bobpassword123" },
      });
      expect(loginResp.status()).toBe(401);
    });
  });

  test.afterAll(async ({ request }) => {
    // Clean up dave — the non-admin delete test creates him but doesn't delete him.
    await request.delete(`${BASE}/api/admin/users/dave`, {
      headers: { Authorization: `Bearer ${aliceToken}` },
    });
  });

  test.describe("Admin deletion (DELETE /api/admin/users/:username)", () => {
    test("admin can delete another user and their sessions are invalidated", async ({ request }) => {
      // Create charlie.
      const charlie = await apiCreateUser(request, BASE, aliceToken, "charlie", "charliepassword123");
      const charlieSession = await apiLogin(request, BASE, "charlie", "charliepassword123", charlie.totpSecret);

      // Admin deletes charlie.
      const deleteResp = await request.delete(`${BASE}/api/admin/users/charlie`, {
        headers: { Authorization: `Bearer ${aliceToken}` },
      });
      expect(deleteResp.ok()).toBe(true);

      // Charlie's refresh token is revoked — refresh must fail.
      const refreshResp = await request.post(`${BASE}/api/auth/refresh`, {
        headers: { "X-CSRF-Token": charlieSession.csrfToken },
      });
      expect(refreshResp.status()).toBe(401);

      // Charlie can no longer log in.
      const loginResp = await request.post(`${BASE}/api/auth/login`, {
        data: { username: "charlie", password: "charliepassword123" },
      });
      expect(loginResp.status()).toBe(401);
    });

    test("admin cannot delete their own account", async ({ request }) => {
      const resp = await request.delete(`${BASE}/api/admin/users/alice`, {
        headers: { Authorization: `Bearer ${aliceToken}` },
      });
      expect(resp.status()).toBe(400);
    });

    test("non-admin cannot delete users", async ({ request }) => {
      const dave = await apiCreateUser(request, BASE, aliceToken, "dave", "davepassword123");
      const daveSession = await apiLogin(request, BASE, "dave", "davepassword123", dave.totpSecret);

      const resp = await request.delete(`${BASE}/api/admin/users/alice`, {
        headers: { Authorization: `Bearer ${daveSession.accessToken}` },
      });
      expect(resp.status()).toBe(403);
    });
  });
});
