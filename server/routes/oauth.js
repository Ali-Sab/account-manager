"use strict";

const crypto  = require("crypto");
const express = require("express");
const router  = express.Router();

const { hashPassword, verifyTOTP, signToken } = require("../lib/crypto");
const {
  getOAuthClient,
  saveOAuthAuthCode, getAndConsumeOAuthAuthCode,
  saveOAuthRefreshToken, getAndRotateOAuthRefreshToken,
  readCredentials, readRefreshTokens,
} = require("../db");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function timingSafeEqual(a, b) {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function getIssuer(req) {
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host  = req.headers["x-forwarded-host"]  || req.get("host");
  return `${proto}://${host}`;
}

// ─── CORS for OAuth endpoints ─────────────────────────────────────────────────

router.use((req, res, next) => {
  const origin = req.headers.origin || "*";
  res.setHeader("Access-Control-Allow-Origin",  origin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ─── Discovery endpoints ──────────────────────────────────────────────────────

router.get(/^\/.well-known\/oauth-protected-resource(\/.*)?$/, (req, res) => {
  const issuer     = getIssuer(req);
  const suffix     = req.path.slice("/.well-known/oauth-protected-resource".length);
  const resourcePath = suffix || "/mcp";
  res.setHeader("Cache-Control", "no-store");
  res.json({
    resource:              `${issuer}${resourcePath}`,
    authorization_servers: [issuer],
  });
});

router.get("/.well-known/oauth-authorization-server", (req, res) => {
  const issuer = getIssuer(req);
  res.setHeader("Cache-Control", "no-store");
  res.json({
    issuer,
    authorization_endpoint:                `${issuer}/authorize`,
    token_endpoint:                        `${issuer}/token`,
    jwks_uri:                              `${issuer}/.well-known/jwks.json`,
    response_types_supported:              ["code"],
    grant_types_supported:                 ["authorization_code", "refresh_token"],
    code_challenge_methods_supported:      ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
  });
});

// ─── Authorization endpoint ───────────────────────────────────────────────────

function authorizePageHtml(client, params, errorMsg) {
  const { client_id, redirect_uri, code_challenge, code_challenge_method, state } = params;
  const clientName = client?.name || client_id;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize — Account Manager</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; color: #1a1a1a; }
    h1 { font-size: 1.2rem; margin-bottom: 0.4rem; }
    p  { color: #555; margin: 0 0 1.5rem; font-size: 0.95rem; }
    label { display: block; font-size: 0.85rem; color: #374151; margin-bottom: 4px; }
    input[type=password], input[type=text] { width: 100%; padding: 8px 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; margin-bottom: 12px; }
    input:focus { outline: 2px solid #2563eb; border-color: transparent; }
    .actions { display: flex; gap: 10px; margin-top: 4px; }
    button { padding: 9px 22px; border-radius: 6px; border: none; font-size: 0.95rem; cursor: pointer; }
    .allow { background: #2563eb; color: #fff; flex: 1; }
    .allow:hover { background: #1d4ed8; }
    .deny  { background: #f3f4f6; color: #374151; }
    .deny:hover { background: #e5e7eb; }
    .error { color: #dc2626; font-size: 0.85rem; margin-bottom: 12px; }
  </style>
</head>
<body>
  <h1>Authorize <strong>${clientName}</strong></h1>
  <p>This will allow <strong>${clientName}</strong> to access your account on your behalf.</p>
  ${errorMsg ? `<div class="error">${errorMsg}</div>` : ""}
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id"             value="${client_id}">
    <input type="hidden" name="redirect_uri"          value="${encodeURIComponent(redirect_uri)}">
    <input type="hidden" name="code_challenge"        value="${code_challenge}">
    <input type="hidden" name="code_challenge_method" value="${code_challenge_method}">
    <input type="hidden" name="state"                 value="${state || ""}">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <label for="totp">2FA code</label>
    <input type="text" id="totp" name="totp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required>
    <div class="actions">
      <button type="submit" name="decision" value="allow" class="allow">Log in &amp; Allow</button>
      <button type="submit" name="decision" value="deny"  class="deny">Deny</button>
    </div>
  </form>
</body>
</html>`;
}

function isAuthedViaRefreshCookie(req) {
  const rt = req.cookies?.refreshToken;
  if (!rt) return false;
  const tokens = readRefreshTokens();
  return tokens[rt] != null && tokens[rt] > Date.now();
}

router.get(["/authorize", "/oauth/authorize"], (req, res) => {
  const { client_id, redirect_uri, response_type, state, code_challenge, code_challenge_method } = req.query;

  if (response_type !== "code") return res.status(400).send("unsupported_response_type");
  const client = getOAuthClient(client_id);
  if (!client) return res.status(400).send("unknown_client");
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send("invalid_redirect_uri");
  if (!code_challenge || code_challenge_method !== "S256") return res.status(400).send("pkce_required");

  if (isAuthedViaRefreshCookie(req)) {
    const code      = crypto.randomBytes(32).toString("hex");
    const expiresAt = Date.now() + 5 * 60 * 1000;
    saveOAuthAuthCode(code, client_id, redirect_uri, code_challenge, code_challenge_method, expiresAt);
    const stateParam = state ? `&state=${encodeURIComponent(state)}` : "";
    return res.redirect(`${redirect_uri}?code=${code}${stateParam}`);
  }

  res.send(authorizePageHtml(client, { client_id, redirect_uri, code_challenge, code_challenge_method, state }));
});

router.post(["/authorize", "/oauth/authorize"], express.urlencoded({ extended: false }), async (req, res) => {
  const { client_id, redirect_uri: encodedUri, code_challenge, code_challenge_method, state, decision, password, totp } = req.body;
  const redirect_uri = decodeURIComponent(encodedUri || "");

  const client = getOAuthClient(client_id);
  if (!client || !client.redirectUris.includes(redirect_uri)) return res.status(400).send("invalid_request");

  const stateParam = state ? `&state=${encodeURIComponent(state)}` : "";
  const params     = { client_id, redirect_uri, code_challenge, code_challenge_method, state };

  if (decision !== "allow") {
    return res.redirect(`${redirect_uri}?error=access_denied${stateParam}`);
  }

  const creds = readCredentials();
  if (!creds) return res.send(authorizePageHtml(client, params, "Server not set up."));

  const hash = await hashPassword(password || "", creds.salt);
  if (hash !== creds.hash) {
    return res.send(authorizePageHtml(client, params, "Incorrect password."));
  }
  if (!verifyTOTP(creds.totpSecret, totp || "")) {
    return res.send(authorizePageHtml(client, params, "Incorrect 2FA code."));
  }

  const code      = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000;
  saveOAuthAuthCode(code, client_id, redirect_uri, code_challenge, code_challenge_method, expiresAt);
  res.redirect(`${redirect_uri}?code=${code}${stateParam}`);
});

// ─── Token endpoint ───────────────────────────────────────────────────────────

function parseTokenBody(req, res, next) {
  const ct = req.headers["content-type"] || "";
  if (ct.includes("application/json")) {
    express.json()(req, res, next);
  } else {
    express.urlencoded({ extended: false })(req, res, next);
  }
}

function extractClientCreds(req, params) {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Basic ")) {
    const decoded = Buffer.from(auth.slice(6), "base64").toString();
    const sep = decoded.indexOf(":");
    if (sep !== -1) {
      return {
        client_id:     decodeURIComponent(decoded.slice(0, sep)),
        client_secret: decodeURIComponent(decoded.slice(sep + 1)),
      };
    }
  }
  return { client_id: params.client_id, client_secret: params.client_secret };
}

router.get(["/token", "/oauth/token"], (req, res) => {
  res.json({ token_endpoint: true });
});

router.post(["/token", "/oauth/token"], parseTokenBody, (req, res) => {
  const params = { ...req.query, ...req.body };
  const { grant_type, code, redirect_uri, code_verifier, refresh_token } = params;
  const { client_id, client_secret } = extractClientCreds(req, params);

  const client = getOAuthClient(client_id);
  if (!client) return res.status(401).json({ error: "invalid_client" });
  if (!timingSafeEqual(sha256(client_secret || ""), client.clientSecretHash)) {
    return res.status(401).json({ error: "invalid_client" });
  }

  if (grant_type === "authorization_code") {
    if (!code || !redirect_uri || !code_verifier) {
      return res.status(400).json({ error: "invalid_request" });
    }
    const record = getAndConsumeOAuthAuthCode(code);
    if (!record || record.clientId !== client_id || record.expiresAt < Date.now()) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    if (record.redirectUri !== redirect_uri) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    const challenge = crypto.createHash("sha256").update(code_verifier).digest("base64url");
    if (challenge !== record.codeChallenge) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    return issueTokens(res, client);
  }

  if (grant_type === "refresh_token") {
    if (!refresh_token) return res.status(400).json({ error: "invalid_request" });
    const record = getAndRotateOAuthRefreshToken(sha256(refresh_token));
    if (!record || record.clientId !== client_id) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    return issueTokens(res, client);
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

function issueTokens(res, client) {
  // Access token expiry differs by audience:
  //   mcp tokens: 30 days (Claude holds them, infrequently rotated)
  //   gamebacklog tokens: 1 hour (relying party redirects back on expiry)
  const isMcp        = client.audience === "mcp";
  const accessExpiry  = isMcp ? "30d" : "1h";
  const accessSeconds = isMcp ? 30 * 24 * 60 * 60 : 60 * 60;

  const creds = readCredentials();
  const sub   = creds?.username || "user";

  const accessToken  = signToken(sub, client.audience, accessExpiry);
  const refreshToken = crypto.randomBytes(32).toString("hex");
  const refreshExpiry = Date.now() + 365 * 24 * 60 * 60 * 1000;

  saveOAuthRefreshToken(sha256(refreshToken), client.clientId, refreshExpiry);

  return res.json({
    access_token:  accessToken,
    token_type:    "bearer",
    expires_in:    accessSeconds,
    refresh_token: refreshToken,
  });
}

module.exports = router;
