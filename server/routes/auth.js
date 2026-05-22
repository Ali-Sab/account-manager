"use strict";

const crypto   = require("crypto");
const express  = require("express");
const rateLimit = require("express-rate-limit");
const router   = express.Router();

const {
  hashPassword, verifyTOTP, generateRecoveryCodes,
  signToken, verifyAccess, signMfaToken, verifyMfaToken,
} = require("../lib/crypto");
const { generateCsrfToken, doubleCsrfProtection } = require("../middleware/csrf");
const requireAuth = require("../middleware/requireAuth");
const {
  readCredentials, writeCredentials,
  readRefreshTokens, writeRefreshTokens,
} = require("../db");

const IS_PROD = process.env.NODE_ENV === "production";

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many attempts, try again in 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === "test",
});

// ─── Refresh token helpers ────────────────────────────────────────────────────

function saveRefreshToken(token) {
  const tokens = readRefreshTokens();
  tokens[token] = Date.now() + 30 * 24 * 60 * 60 * 1000;
  for (const [k, exp] of Object.entries(tokens)) {
    if (exp < Date.now()) delete tokens[k];
  }
  writeRefreshTokens(tokens);
}

function validateRefreshToken(token) {
  const tokens = readRefreshTokens();
  return tokens[token] && tokens[token] > Date.now();
}

function revokeRefreshToken(token) {
  const tokens = readRefreshTokens();
  delete tokens[token];
  writeRefreshTokens(tokens);
}

function issueSession(res, username) {
  const accessToken  = signToken(username, "account-manager", "1h");
  const refreshToken = crypto.randomBytes(48).toString("hex");
  saveRefreshToken(refreshToken);
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure:   IS_PROD,
    sameSite: "strict",
    maxAge:   30 * 24 * 60 * 60 * 1000,
    path:     "/",
  });
  return accessToken;
}

async function consumeRecoveryCode(creds, code) {
  const c = (code || "").trim().toLowerCase();
  if (!c) return false;
  const candidate = await hashPassword(c, creds.salt);
  const idx = (creds.recoveryCodes || []).findIndex(h => h === candidate);
  if (idx === -1) return false;
  const remaining = [...creds.recoveryCodes];
  remaining.splice(idx, 1);
  writeCredentials({ ...creds, recoveryCodes: remaining });
  return true;
}

// ─── Auth endpoints ───────────────────────────────────────────────────────────

router.post("/auth/login", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const creds = readCredentials();
    if (!creds) return res.status(400).json({ error: "Not configured" });
    if (creds.username !== username?.trim()) {
      await hashPassword(password || "", creds.salt);
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const hash = await hashPassword(password || "", creds.salt);
    if (hash !== creds.hash) return res.status(401).json({ error: "Invalid credentials" });
    const mfaToken = signMfaToken(username.trim());
    res.json({ mfaToken });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Login failed" });
  }
});

router.post("/auth/mfa", authLimiter, (req, res) => {
  try {
    const { mfaToken, code } = req.body;
    const payload = verifyMfaToken(mfaToken);
    if (!payload) return res.status(401).json({ error: "Invalid token" });
    const creds = readCredentials();
    if (!verifyTOTP(creds.totpSecret, code)) {
      return res.status(401).json({ error: "Invalid MFA code" });
    }
    const accessToken = issueSession(res, payload.sub);
    const csrfToken   = generateCsrfToken(req, res);
    res.json({ accessToken, csrfToken });
  } catch (e) {
    res.status(401).json({ error: "MFA failed" });
  }
});

router.post("/auth/recovery", authLimiter, async (req, res) => {
  try {
    const { mfaToken, code } = req.body;
    const payload = verifyMfaToken(mfaToken);
    if (!payload) return res.status(401).json({ error: "Invalid token" });
    const creds = readCredentials();
    if (!creds || !creds.recoveryCodes?.length) {
      return res.status(401).json({ error: "No recovery codes available" });
    }
    const ok = await consumeRecoveryCode(creds, code);
    if (!ok) return res.status(401).json({ error: "Invalid recovery code" });
    const remaining   = readCredentials().recoveryCodes.length;
    const accessToken = issueSession(res, payload.sub);
    const csrfToken   = generateCsrfToken(req, res);
    res.json({ accessToken, csrfToken, remaining });
  } catch (e) {
    res.status(401).json({ error: "Recovery failed" });
  }
});

router.post("/auth/recovery-codes/regenerate", requireAuth, async (req, res) => {
  const creds = readCredentials();
  if (!creds) return res.status(400).json({ error: "Not configured" });
  const { plain, hashes } = await generateRecoveryCodes(creds.salt);
  writeCredentials({ ...creds, recoveryCodes: hashes });
  res.json({ recoveryCodes: plain });
});

router.get("/auth/recovery-codes/count", requireAuth, (req, res) => {
  const creds = readCredentials();
  res.json({ remaining: creds?.recoveryCodes?.length ?? 0 });
});

router.get("/auth/csrf", (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

router.post("/auth/refresh", authLimiter, doubleCsrfProtection, (req, res) => {
  const rt = req.cookies?.refreshToken;
  if (!rt || !validateRefreshToken(rt)) {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }
  const creds = readCredentials();
  if (!creds) return res.status(401).json({ error: "Not configured" });
  const accessToken = signToken(creds.username, "account-manager", "1h");
  res.json({ accessToken });
});

router.post("/auth/logout", doubleCsrfProtection, (req, res) => {
  const rt = req.cookies?.refreshToken;
  if (rt) revokeRefreshToken(rt);
  res.clearCookie("refreshToken", { path: "/" });
  res.json({ ok: true });
});

router.post("/auth/change-password", requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: "New password too short" });
    const creds = readCredentials();
    const hash = await hashPassword(currentPassword || "", creds.salt);
    if (hash !== creds.hash) return res.status(401).json({ error: "Current password incorrect" });
    const salt   = crypto.randomBytes(32).toString("hex");
    const newHash = await hashPassword(newPassword, salt);
    const { plain, hashes } = await generateRecoveryCodes(salt);
    writeCredentials({ ...creds, hash: newHash, salt, recoveryCodes: hashes });
    writeRefreshTokens({});
    res.clearCookie("refreshToken", { path: "/" });
    res.json({ ok: true, recoveryCodes: plain });
  } catch (e) {
    res.status(500).json({ error: "Password change failed" });
  }
});

module.exports = router;
