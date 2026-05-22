"use strict";

const crypto = require("crypto");
const jwt    = require("jsonwebtoken");
const { generateSync: _otpGenerate, verifySync: _otpVerify, generateSecret: _otpSecret } = require("otplib");
const { createGuardrails: _createGuardrails } = require("@otplib/core");

const _otpGuardrails = { ..._createGuardrails(), MIN_SECRET_BYTES: 0 };

// Lazy-load keys so this module can be required before setup runs (e.g. in tests)
let _keys = null;
function keys() {
  if (!_keys) _keys = require("./keys");
  return _keys;
}

function getIssuer() {
  return process.env.JWT_ISSUER || "http://localhost:3001";
}

function hashPassword(password, salt) {
  return new Promise((res, rej) =>
    crypto.pbkdf2(password, salt, 310000, 64, "sha512",
      (err, key) => err ? rej(err) : res(key.toString("hex")))
  );
}

function computeTOTP(secret, offset = 0) {
  const epoch = Math.floor(Date.now() / 1000) + offset * 30;
  return _otpGenerate({ secret, epoch, guardrails: _otpGuardrails });
}

function verifyTOTP(secret, code) {
  const c = (code || "").replace(/\s/g, "");
  if (c.length !== 6) return false;
  return _otpVerify({ secret, token: c, epochTolerance: 30, guardrails: _otpGuardrails }).valid;
}

function generateSecret() {
  return _otpSecret(20);
}

function newRecoveryCode() {
  const raw = crypto.randomBytes(5).toString("hex");
  return `${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8,10)}`;
}

async function generateRecoveryCodes(salt, n = 8) {
  const plain = Array.from({ length: n }, newRecoveryCode);
  const hashes = await Promise.all(plain.map(c => hashPassword(c, salt)));
  return { plain, hashes };
}

// Sign an RS256 JWT. audience can be 'account-manager', 'gamebacklog', or 'mcp'.
function signToken(sub, audience, expiresIn = "1h") {
  return jwt.sign(
    { sub, aud: audience },
    keys().privateKey,
    { algorithm: "RS256", expiresIn, issuer: getIssuer() }
  );
}

// Verify an RS256 JWT issued by this server, for the account-manager UI.
function verifyAccess(token) {
  try {
    return jwt.verify(token, keys().publicKey, {
      algorithms: ["RS256"],
      audience:   "account-manager",
      issuer:     getIssuer(),
    });
  } catch { return null; }
}

// Short-lived step token between login step 1 and MFA step 2.
function signMfaToken(username) {
  return jwt.sign(
    { sub: username, mfaPending: true },
    keys().privateKey,
    { algorithm: "RS256", expiresIn: "5m", issuer: getIssuer() }
  );
}

function verifyMfaToken(token) {
  try {
    const p = jwt.verify(token, keys().publicKey, { algorithms: ["RS256"], issuer: getIssuer() });
    return p.mfaPending ? p : null;
  } catch { return null; }
}

module.exports = {
  hashPassword,
  computeTOTP, verifyTOTP, generateSecret,
  newRecoveryCode, generateRecoveryCodes,
  signToken, verifyAccess,
  signMfaToken, verifyMfaToken,
};
