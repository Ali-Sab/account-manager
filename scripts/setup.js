"use strict";

const path   = require("path");
const fs     = require("fs");
const crypto = require("crypto");

require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const DATA_DIR  = process.env.DATA_DIR  || path.resolve(__dirname, "..", "data");
const KEYS_DIR  = path.join(DATA_DIR, "keys");
const PRIV_PATH = path.join(KEYS_DIR, "private.pem");
const PUB_PATH  = path.join(KEYS_DIR, "public.pem");

// ─── 1. Ensure directories exist ─────────────────────────────────────────────

fs.mkdirSync(KEYS_DIR, { recursive: true });

// ─── 2. Generate RSA key pair if absent ──────────────────────────────────────

if (!fs.existsSync(PRIV_PATH) || !fs.existsSync(PUB_PATH)) {
  console.log("[setup] Generating RSA-2048 key pair...");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  fs.writeFileSync(PRIV_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUB_PATH,  publicKey,  { mode: 0o644 });
  console.log("[setup] Keys written to", KEYS_DIR);
} else {
  console.log("[setup] RSA keys already exist, skipping generation");
}

// ─── 3. Run DB migrations ─────────────────────────────────────────────────────

process.env.PRIVATE_KEY_PATH = PRIV_PATH;
process.env.PUBLIC_KEY_PATH  = PUB_PATH;

require("../server/db");
console.log("[setup] Database schema up to date");

// ─── 4. Seed OAuth clients ────────────────────────────────────────────────────

const { getOAuthClient, upsertOAuthClient } = require("../server/db");

function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
function genId()     { return crypto.randomUUID(); }
function genSecret() { return crypto.randomBytes(32).toString("hex"); }

// Stable lookup key stored in the DB for each well-known client.
// If you need to rotate credentials, delete the row and re-run setup.
const MCP_CLIENT_LOOKUP = "claude-mcp";
const GB_CLIENT_LOOKUP  = "gamebacklog-web";

const newCredentials = [];

// ── MCP client (Claude.ai) ────────────────────────────────────────────────────
let mcpClient = getOAuthClient(MCP_CLIENT_LOOKUP);
if (!mcpClient) {
  const clientId     = genId();
  const clientSecret = genSecret();
  upsertOAuthClient({
    clientId:         MCP_CLIENT_LOOKUP,
    clientSecretHash: sha256(clientSecret),
    redirectUris:     ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"],
    name:             "Claude",
    audience:         "mcp",
  });
  // Store the plaintext secret alongside so we can print it below.
  // We re-read after insert so the shape is consistent.
  newCredentials.push({
    label:        "Claude MCP (enter these in Claude.ai → Settings → Integrations)",
    clientId:     MCP_CLIENT_LOOKUP,
    clientSecret,
  });
  console.log("[setup] MCP OAuth client created");
} else {
  console.log("[setup] MCP OAuth client already exists, skipping");
}

// ── Game Backlog web client (PKCE login flow) ─────────────────────────────────
let gbClient = getOAuthClient(GB_CLIENT_LOOKUP);
if (!gbClient) {
  const clientId     = genId();
  const clientSecret = genSecret();
  const redirectUri  = process.env.GAMEBACKLOG_REDIRECT_URI || "http://localhost:3000/auth/callback";
  upsertOAuthClient({
    clientId:         GB_CLIENT_LOOKUP,
    clientSecretHash: sha256(clientSecret),
    redirectUris:     [redirectUri],
    name:             "Game Backlog",
    audience:         "gamebacklog",
  });
  newCredentials.push({
    label:        "Game Backlog web client (copy these into gamebacklog/.env)",
    clientId:     GB_CLIENT_LOOKUP,
    clientSecret,
  });
  console.log("[setup] Game Backlog OAuth client created");
} else {
  console.log("[setup] Game Backlog OAuth client already exists, skipping");
}

// ─── 5. Print newly generated credentials ────────────────────────────────────

if (newCredentials.length > 0) {
  const line = "─".repeat(60);
  console.log("\n" + line);
  console.log("  SAVE THESE CREDENTIALS — they will not be shown again");
  console.log(line);
  for (const c of newCredentials) {
    console.log(`\n  ${c.label}`);
    console.log(`    CLIENT_ID:     ${c.clientId}`);
    console.log(`    CLIENT_SECRET: ${c.clientSecret}`);
  }
  console.log("\n" + line + "\n");
}

console.log("[setup] Done.");
