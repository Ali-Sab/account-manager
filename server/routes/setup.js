"use strict";

const crypto   = require("crypto");
const QRCode   = require("qrcode");
const express  = require("express");
const rateLimit = require("express-rate-limit");
const router   = express.Router();

const { hashPassword, verifyTOTP, generateSecret, generateRecoveryCodes } = require("../lib/crypto");
const {
  readCredentials, writeCredentials,
  readPasskeyCredentials,
  readPendingSetup, writePendingSetup,
} = require("../db");

const setupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many attempts, try again in 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === "test",
});

router.get("/setup/status", (req, res) => {
  const creds    = readCredentials();
  const passkeys = readPasskeyCredentials();
  res.json({ configured: !!creds, hasPasskeys: passkeys.length > 0 });
});

router.get("/setup/secret", async (req, res) => {
  const creds = readCredentials();
  if (creds) return res.status(403).json({ error: "Already configured" });
  const secret = generateSecret();
  writePendingSetup({ secret, createdAt: Date.now() });
  const uri = `otpauth://totp/AccountManager:setup?secret=${secret}&issuer=AccountManager`;
  const qrDataUrl = await QRCode.toDataURL(uri);
  res.json({ secret, formatted: secret.match(/.{1,4}/g).join(" "), qrDataUrl });
});

router.post("/setup", setupLimiter, async (req, res) => {
  try {
    const creds = readCredentials();
    if (creds) return res.status(403).json({ error: "Already configured" });
    const { username, password, totpCode } = req.body;
    if (!username || !password || !totpCode) return res.status(400).json({ error: "Missing fields" });
    if (password.length < 6) return res.status(400).json({ error: "Password too short" });
    const pending = readPendingSetup();
    if (!pending || Date.now() - pending.createdAt > 10 * 60 * 1000) {
      return res.status(400).json({ error: "Setup session expired, refresh the page" });
    }
    if (!verifyTOTP(pending.secret, totpCode)) {
      return res.status(400).json({ error: "Invalid TOTP code" });
    }
    const salt = crypto.randomBytes(32).toString("hex");
    const hash = await hashPassword(password, salt);
    const { plain, hashes } = await generateRecoveryCodes(salt);
    writeCredentials({
      username: username.trim(), hash, salt,
      totpSecret: pending.secret,
      recoveryCodes: hashes,
    });
    writePendingSetup(null);
    res.json({ ok: true, recoveryCodes: plain });
  } catch (e) {
    console.error("Setup error:", e);
    res.status(500).json({ error: "Setup failed" });
  }
});

module.exports = router;
