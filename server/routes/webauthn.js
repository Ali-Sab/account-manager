"use strict";

const crypto   = require("crypto");
const express  = require("express");
const rateLimit = require("express-rate-limit");
const router   = express.Router();

const { signToken } = require("../lib/crypto");
const requireAuth = require("../middleware/requireAuth");
const {
  readCredentials, writeCredentials,
  readPasskeyCredentials, writePasskeyCredential, deletePasskeyCredential,
  readWebAuthnChallenge, writeWebAuthnChallenge,
  readSetupState, writeSetupState,
  readRefreshTokens,
  db,
} = require("../db");

const IS_PROD          = process.env.NODE_ENV === "production";
const WEBAUTHN_RP_ID   = process.env.WEBAUTHN_RP_ID   || "localhost";
const WEBAUTHN_RP_NAME = process.env.WEBAUTHN_RP_NAME || "Account Manager";

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { error: "Too many attempts, try again in 15 minutes" },
  standardHeaders: true, legacyHeaders: false,
  skip: () => process.env.NODE_ENV === "test",
});

let _webauthn = null;
async function getWebAuthn() {
  if (!_webauthn) _webauthn = await import("@simplewebauthn/server");
  return _webauthn;
}

function getOrigin(req) {
  return req.headers.origin || `${req.protocol}://${req.get("host")}`;
}

function saveRefreshToken(token) {
  const { readRefreshTokens, writeRefreshTokens } = require("../db");
  const tokens = readRefreshTokens();
  tokens[token] = Date.now() + 30 * 24 * 60 * 60 * 1000;
  for (const [k, exp] of Object.entries(tokens)) {
    if (exp < Date.now()) delete tokens[k];
  }
  writeRefreshTokens(tokens);
}

// ─── Registration (new user, no creds yet) ────────────────────────────────────

router.post("/webauthn/register/start", authLimiter, async (req, res) => {
  try {
    const creds = readCredentials();
    if (creds) return res.status(403).json({ error: "Already configured" });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing fields" });
    if (password.length < 6) return res.status(400).json({ error: "Password too short" });
    const { hashPassword } = require("../lib/crypto");
    const salt = crypto.randomBytes(32).toString("hex");
    const hash = await hashPassword(password, salt);
    const { generateRegistrationOptions } = await getWebAuthn();
    const options = await generateRegistrationOptions({
      rpName: WEBAUTHN_RP_NAME,
      rpID:   WEBAUTHN_RP_ID,
      userID: new TextEncoder().encode(username.trim()),
      userName: username.trim(),
      attestationType: "none",
      authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
    });
    writeSetupState({ username: username.trim(), hash, salt, challenge: options.challenge, createdAt: Date.now() });
    res.json(options);
  } catch (e) {
    console.error("WebAuthn register/start error:", e);
    res.status(500).json({ error: "Registration start failed" });
  }
});

router.post("/webauthn/register/finish", authLimiter, async (req, res) => {
  try {
    const creds = readCredentials();
    if (creds) return res.status(403).json({ error: "Already configured" });
    const state = readSetupState();
    if (!state || Date.now() - state.createdAt > 10 * 60 * 1000) {
      return res.status(400).json({ error: "Registration session expired" });
    }
    const { verifyRegistrationResponse } = await getWebAuthn();
    const verification = await verifyRegistrationResponse({
      response:          req.body,
      expectedChallenge: state.challenge,
      expectedOrigin:    getOrigin(req),
      expectedRPID:      WEBAUTHN_RP_ID,
    });
    if (!verification.verified) return res.status(400).json({ error: "Verification failed" });
    const { credential } = verification.registrationInfo;
    db.transaction(() => {
      writeCredentials({ username: state.username, hash: state.hash, salt: state.salt, totpSecret: "" });
      writeSetupState(null);
      writePasskeyCredential({
        credentialId: credential.id,
        publicKey:    Buffer.from(credential.publicKey).toString("base64"),
        counter:      credential.counter,
        deviceName:   req.body.deviceName || "Device 1",
        createdAt:    new Date().toISOString(),
      });
    })();
    res.json({ ok: true });
  } catch (e) {
    console.error("WebAuthn register/finish error:", e);
    res.status(500).json({ error: "Registration failed" });
  }
});

// ─── Add device (authenticated user) ─────────────────────────────────────────

router.post("/webauthn/add-device/start", requireAuth, async (req, res) => {
  try {
    const creds    = readCredentials();
    const existing = readPasskeyCredentials();
    const { generateRegistrationOptions } = await getWebAuthn();
    const options = await generateRegistrationOptions({
      rpName: WEBAUTHN_RP_NAME,
      rpID:   WEBAUTHN_RP_ID,
      userID: new TextEncoder().encode(creds.username),
      userName: creds.username,
      attestationType: "none",
      excludeCredentials: existing.map(p => ({ id: p.credentialId, type: "public-key" })),
      authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
    });
    writeWebAuthnChallenge({ challenge: options.challenge, createdAt: Date.now() });
    res.json(options);
  } catch (e) {
    console.error("WebAuthn add-device/start error:", e);
    res.status(500).json({ error: "Failed to start" });
  }
});

router.post("/webauthn/add-device/finish", requireAuth, async (req, res) => {
  try {
    const state = readWebAuthnChallenge();
    if (!state || Date.now() - state.createdAt > 10 * 60 * 1000) {
      return res.status(400).json({ error: "Session expired" });
    }
    const { verifyRegistrationResponse } = await getWebAuthn();
    const verification = await verifyRegistrationResponse({
      response:          req.body,
      expectedChallenge: state.challenge,
      expectedOrigin:    getOrigin(req),
      expectedRPID:      WEBAUTHN_RP_ID,
    });
    if (!verification.verified) return res.status(400).json({ error: "Verification failed" });
    const { credential } = verification.registrationInfo;
    const existing = readPasskeyCredentials();
    writePasskeyCredential({
      credentialId: credential.id,
      publicKey:    Buffer.from(credential.publicKey).toString("base64"),
      counter:      credential.counter,
      deviceName:   req.body.deviceName || `Device ${existing.length + 1}`,
      createdAt:    new Date().toISOString(),
    });
    writeWebAuthnChallenge(null);
    res.json({ ok: true });
  } catch (e) {
    console.error("WebAuthn add-device/finish error:", e);
    res.status(500).json({ error: "Failed to register device" });
  }
});

// ─── Login ────────────────────────────────────────────────────────────────────

router.post("/webauthn/login/start", authLimiter, async (req, res) => {
  try {
    const passkeys = readPasskeyCredentials();
    if (passkeys.length === 0) return res.status(400).json({ error: "No passkeys registered" });
    const { generateAuthenticationOptions } = await getWebAuthn();
    const options = await generateAuthenticationOptions({
      rpID:             WEBAUTHN_RP_ID,
      allowCredentials: passkeys.map(p => ({ id: p.credentialId, type: "public-key" })),
      userVerification: "preferred",
    });
    writeWebAuthnChallenge({ challenge: options.challenge, createdAt: Date.now() });
    res.json(options);
  } catch (e) {
    console.error("WebAuthn login/start error:", e);
    res.status(500).json({ error: "Login start failed" });
  }
});

router.post("/webauthn/login/finish", authLimiter, async (req, res) => {
  try {
    const state = readWebAuthnChallenge();
    if (!state || Date.now() - state.createdAt > 5 * 60 * 1000) {
      return res.status(400).json({ error: "Authentication session expired" });
    }
    const passkeys = readPasskeyCredentials();
    const passkey  = passkeys.find(p => p.credentialId === req.body.id);
    if (!passkey) return res.status(400).json({ error: "Unknown credential" });
    const { verifyAuthenticationResponse } = await getWebAuthn();
    const verification = await verifyAuthenticationResponse({
      response:          req.body,
      expectedChallenge: state.challenge,
      expectedOrigin:    getOrigin(req),
      expectedRPID:      WEBAUTHN_RP_ID,
      credential: {
        id:        passkey.credentialId,
        publicKey: Buffer.from(passkey.publicKey, "base64"),
        counter:   passkey.counter,
      },
    });
    if (!verification.verified) return res.status(401).json({ error: "Authentication failed" });
    writePasskeyCredential({ ...passkey, counter: verification.authenticationInfo.newCounter });
    writeWebAuthnChallenge(null);
    const creds        = readCredentials();
    const accessToken  = signToken(creds.username, "account-manager", "1h");
    const refreshToken = crypto.randomBytes(48).toString("hex");
    saveRefreshToken(refreshToken);
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, secure: IS_PROD, sameSite: "strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, path: "/",
    });
    res.json({ accessToken });
  } catch (e) {
    console.error("WebAuthn login/finish error:", e);
    res.status(401).json({ error: "Authentication failed" });
  }
});

router.get("/webauthn/credentials", requireAuth, (req, res) => {
  const passkeys = readPasskeyCredentials();
  res.json(passkeys.map(p => ({ credentialId: p.credentialId, deviceName: p.deviceName, createdAt: p.createdAt })));
});

router.delete("/webauthn/credentials/:id", requireAuth, (req, res) => {
  const passkeys = readPasskeyCredentials();
  if (passkeys.length <= 1) {
    return res.status(400).json({ error: "Cannot remove last passkey — register another device first" });
  }
  deletePasskeyCredential(decodeURIComponent(req.params.id));
  res.json({ ok: true });
});

module.exports = router;
