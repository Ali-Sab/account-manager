"use strict";

const Database = require("better-sqlite3");
const path     = require("path");
const fs       = require("fs");

const DATA_DIR = process.env.DATA_DIR || path.resolve(__dirname, "..", "data");
const DB_PATH  = process.env.DB_PATH  || path.resolve(DATA_DIR, "account-manager.db");

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    username        TEXT NOT NULL,
    hash            TEXT NOT NULL,
    salt            TEXT NOT NULL,
    totp_secret     TEXT NOT NULL,
    recovery_codes  TEXT
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS pending_setup (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    secret     TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS passkey_credentials (
    credential_id TEXT PRIMARY KEY,
    public_key    TEXT NOT NULL,
    counter       INTEGER NOT NULL DEFAULT 0,
    device_name   TEXT,
    created_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    challenge  TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS setup_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    username    TEXT,
    hash        TEXT,
    salt        TEXT,
    challenge   TEXT,
    created_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id          TEXT PRIMARY KEY,
    client_secret_hash TEXT NOT NULL,
    redirect_uris      TEXT NOT NULL,
    name               TEXT,
    audience           TEXT NOT NULL DEFAULT 'mcp'
  );

  CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    code                   TEXT PRIMARY KEY,
    client_id              TEXT NOT NULL,
    redirect_uri           TEXT NOT NULL,
    code_challenge         TEXT,
    code_challenge_method  TEXT,
    expires_at             INTEGER NOT NULL,
    used                   INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash  TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
  );
`);

// ─── Credentials ──────────────────────────────────────────────────────────────

function readCredentials() {
  const row = db.prepare("SELECT * FROM credentials WHERE id = 1").get();
  if (!row) return null;
  return {
    username:      row.username,
    hash:          row.hash,
    salt:          row.salt,
    totpSecret:    row.totp_secret,
    recoveryCodes: row.recovery_codes ? JSON.parse(row.recovery_codes) : [],
  };
}

function writeCredentials(creds) {
  db.prepare(`
    INSERT INTO credentials (id, username, hash, salt, totp_secret, recovery_codes)
    VALUES (1, @username, @hash, @salt, @totp_secret, @recovery_codes)
    ON CONFLICT(id) DO UPDATE SET
      username=excluded.username, hash=excluded.hash,
      salt=excluded.salt, totp_secret=excluded.totp_secret,
      recovery_codes=excluded.recovery_codes
  `).run({
    username:       creds.username,
    hash:           creds.hash,
    salt:           creds.salt,
    totp_secret:    creds.totpSecret,
    recovery_codes: creds.recoveryCodes ? JSON.stringify(creds.recoveryCodes) : null,
  });
}

// ─── Refresh tokens ───────────────────────────────────────────────────────────

function readRefreshTokens() {
  const rows = db.prepare("SELECT token, expires_at FROM refresh_tokens").all();
  const result = {};
  for (const row of rows) result[row.token] = row.expires_at;
  return result;
}

function writeRefreshTokens(tokensObj) {
  const replace = db.transaction((obj) => {
    db.prepare("DELETE FROM refresh_tokens").run();
    const ins = db.prepare("INSERT INTO refresh_tokens (token, expires_at) VALUES (?, ?)");
    for (const [token, exp] of Object.entries(obj)) ins.run(token, exp);
  });
  replace(tokensObj);
}

// ─── Pending setup ────────────────────────────────────────────────────────────

function readPendingSetup() {
  const row = db.prepare("SELECT * FROM pending_setup WHERE id = 1").get();
  if (!row) return null;
  return { secret: row.secret, createdAt: row.created_at };
}

function writePendingSetup(obj) {
  if (obj === null) {
    db.prepare("DELETE FROM pending_setup WHERE id = 1").run();
    return;
  }
  db.prepare(`
    INSERT INTO pending_setup (id, secret, created_at) VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, created_at=excluded.created_at
  `).run(obj.secret, obj.createdAt);
}

// ─── Passkey credentials ──────────────────────────────────────────────────────

function readPasskeyCredentials() {
  return db.prepare("SELECT * FROM passkey_credentials").all().map(row => ({
    credentialId: row.credential_id,
    publicKey:    row.public_key,
    counter:      row.counter,
    deviceName:   row.device_name,
    createdAt:    row.created_at,
  }));
}

function writePasskeyCredential(cred) {
  db.prepare(`
    INSERT INTO passkey_credentials (credential_id, public_key, counter, device_name, created_at)
    VALUES (@credential_id, @public_key, @counter, @device_name, @created_at)
    ON CONFLICT(credential_id) DO UPDATE SET
      public_key=excluded.public_key, counter=excluded.counter,
      device_name=excluded.device_name
  `).run({
    credential_id: cred.credentialId,
    public_key:    cred.publicKey,
    counter:       cred.counter ?? 0,
    device_name:   cred.deviceName ?? null,
    created_at:    cred.createdAt ?? new Date().toISOString(),
  });
}

function deletePasskeyCredential(credentialId) {
  db.prepare("DELETE FROM passkey_credentials WHERE credential_id = ?").run(credentialId);
}

// ─── WebAuthn challenge ───────────────────────────────────────────────────────

function readWebAuthnChallenge() {
  const row = db.prepare("SELECT * FROM webauthn_challenges WHERE id = 1").get();
  if (!row) return null;
  return { challenge: row.challenge, createdAt: row.created_at };
}

function writeWebAuthnChallenge(obj) {
  if (obj === null) {
    db.prepare("DELETE FROM webauthn_challenges WHERE id = 1").run();
    return;
  }
  db.prepare(`
    INSERT INTO webauthn_challenges (id, challenge, created_at) VALUES (1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET challenge=excluded.challenge, created_at=excluded.created_at
  `).run(obj.challenge, obj.createdAt);
}

// ─── Setup state ──────────────────────────────────────────────────────────────

function readSetupState() {
  const row = db.prepare("SELECT * FROM setup_state WHERE id = 1").get();
  if (!row) return null;
  return { username: row.username, hash: row.hash, salt: row.salt, challenge: row.challenge, createdAt: row.created_at };
}

function writeSetupState(obj) {
  if (obj === null) {
    db.prepare("DELETE FROM setup_state WHERE id = 1").run();
    return;
  }
  db.prepare(`
    INSERT INTO setup_state (id, username, hash, salt, challenge, created_at)
    VALUES (1, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      username=excluded.username, hash=excluded.hash, salt=excluded.salt,
      challenge=excluded.challenge, created_at=excluded.created_at
  `).run(obj.username, obj.hash, obj.salt, obj.challenge, obj.createdAt);
}

// ─── OAuth ────────────────────────────────────────────────────────────────────

function getOAuthClient(clientId) {
  const row = db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(clientId);
  if (!row) return null;
  return {
    clientId:         row.client_id,
    clientSecretHash: row.client_secret_hash,
    redirectUris:     JSON.parse(row.redirect_uris),
    name:             row.name,
    audience:         row.audience,
  };
}

function upsertOAuthClient(client) {
  db.prepare(`
    INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris, name, audience)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(client_id) DO UPDATE SET
      client_secret_hash=excluded.client_secret_hash,
      redirect_uris=excluded.redirect_uris,
      name=excluded.name,
      audience=excluded.audience
  `).run(
    client.clientId,
    client.clientSecretHash,
    JSON.stringify(client.redirectUris),
    client.name ?? null,
    client.audience ?? "mcp",
  );
}

function saveOAuthAuthCode(code, clientId, redirectUri, codeChallenge, codeChallengeMethod, expiresAt) {
  db.prepare(`
    INSERT INTO oauth_auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, expires_at, used)
    VALUES (?, ?, ?, ?, ?, ?, 0)
  `).run(code, clientId, redirectUri, codeChallenge ?? null, codeChallengeMethod ?? null, expiresAt);
}

function getAndConsumeOAuthAuthCode(code) {
  const row = db.prepare("SELECT * FROM oauth_auth_codes WHERE code = ? AND used = 0").get(code);
  if (!row) return null;
  db.prepare("UPDATE oauth_auth_codes SET used = 1 WHERE code = ?").run(code);
  return {
    code:                row.code,
    clientId:            row.client_id,
    redirectUri:         row.redirect_uri,
    codeChallenge:       row.code_challenge,
    codeChallengeMethod: row.code_challenge_method,
    expiresAt:           row.expires_at,
  };
}

function saveOAuthRefreshToken(tokenHash, clientId, expiresAt) {
  db.prepare("INSERT INTO oauth_refresh_tokens (token_hash, client_id, expires_at) VALUES (?, ?, ?)").run(tokenHash, clientId, expiresAt);
}

function getAndRotateOAuthRefreshToken(tokenHash) {
  const row = db.prepare("SELECT * FROM oauth_refresh_tokens WHERE token_hash = ? AND expires_at > ?").get(tokenHash, Date.now());
  if (!row) return null;
  db.prepare("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?").run(tokenHash);
  return { clientId: row.client_id, expiresAt: row.expires_at };
}

module.exports = {
  db,
  readCredentials, writeCredentials,
  readRefreshTokens, writeRefreshTokens,
  readPendingSetup, writePendingSetup,
  readPasskeyCredentials, writePasskeyCredential, deletePasskeyCredential,
  readWebAuthnChallenge, writeWebAuthnChallenge,
  readSetupState, writeSetupState,
  getOAuthClient, upsertOAuthClient,
  saveOAuthAuthCode, getAndConsumeOAuthAuthCode,
  saveOAuthRefreshToken, getAndRotateOAuthRefreshToken,
};
