# account-manager

Standalone auth service and account portal. It is both a Node.js backend (Express + SQLite) and a React CSR frontend (Vite). Other services are relying parties — they redirect here for login and verify the RS256 JWTs it issues.

## Repo layout

```
scripts/setup.js      — idempotent startup: RSA keys, DB migrations, OAuth client seeding
server/
  index.js            — process entry point (listen)
  app.js              — Express wiring, route mounts, SPA fallback
  db.js               — SQLite via better-sqlite3; auth tables only (no game data)
  lib/
    keys.js           — loads RSA keypair from DATA_DIR/keys/; exports privateKey, publicKey, jwks
    crypto.js         — signToken, verifyAccess, signMfaToken, verifyMfaToken, hashPassword, TOTP
  middleware/
    requireAuth.js    — RS256 JWT check (audience: account-manager)
    csrf.js           — double-submit CSRF via csrf-csrf
  routes/
    auth.js           — login, MFA, refresh, logout, password change, recovery codes
    setup.js          — first-run account creation (username, password, TOTP)
    webauthn.js       — passkey registration and authentication
    oauth.js          — OAuth 2.0 server: /authorize, /token, discovery endpoints
    jwks.js           — GET /.well-known/jwks.json
src/                  — React CSR app
  screens/
    SetupScreen.tsx   — first-run wizard
    LoginScreen.tsx   — password + TOTP login
    AccountScreen.tsx — passkey management, change password, recovery codes
  context/AuthContext.tsx  — boots via POST /api/auth/refresh
```

## Startup

```bash
npm run setup   # generates RSA keys, runs DB migrations, seeds OAuth clients — safe to re-run
npm start       # production
npm run dev     # dev: Express (--watch) + Vite in parallel
```

`npm run setup` prints generated client credentials to stdout on first run. Save them — they are not shown again.

## Token design

All tokens are RS256 JWTs signed with the private key in `DATA_DIR/keys/private.pem`.

| Audience | Issued to | Expiry | Used by |
|---|---|---|---|
| `account-manager` | account-manager React SPA | 1h | account-manager UI routes |
| `gamebacklog` | game backlog app (via PKCE flow) | 1h | gamebacklog API |
| `mcp` | Claude.ai (via MCP OAuth flow) | 30d | MCP server in gamebacklog |

`signToken(sub, audience, expiresIn)` is the single signing function. Relying parties verify locally using the public key from `/.well-known/jwks.json` — no round-trip to account-manager needed.

## OAuth clients

Two well-known clients are seeded by `scripts/setup.js`:

- `claude-mcp` — Claude.ai's MCP connector. Audience `mcp`.
- `gamebacklog-web` — game backlog PKCE login flow. Audience `gamebacklog`.

Client credentials are auto-generated on first setup and stored hashed in SQLite. The plaintext secret is only printed once at setup time. To rotate: delete the row from `oauth_clients` and re-run `npm run setup`.

The `/authorize` endpoint accepts already-authenticated users (valid `refreshToken` cookie) without prompting for credentials — the consent page only appears when the session is absent.

## Login flow (account-manager UI)

1. `POST /api/auth/login` — password check → returns short-lived `mfaToken` (RS256, 5m, `mfaPending: true`)
2. `POST /api/auth/mfa` — TOTP check → sets `refreshToken` httpOnly cookie (30d), returns `accessToken` (1h)
3. On subsequent loads: `POST /api/auth/refresh` (requires CSRF token) → returns fresh `accessToken`

## Database (SQLite)

Auth tables only — no game data. Key tables: `credentials`, `refresh_tokens`, `passkey_credentials`, `webauthn_challenges`, `setup_state`, `pending_setup`, `oauth_clients`, `oauth_auth_codes`, `oauth_refresh_tokens`.

DB file lives at `DATA_DIR/account-manager.db` (default: `./data/account-manager.db`).

## Environment variables

See `.env.example`. Key vars:

```
PORT=3001
DATA_DIR=./data
CSRF_SECRET=
JWT_ISSUER=http://localhost:3001       # must match the issuer claim in tokens
WEBAUTHN_RP_ID=localhost
GAMEBACKLOG_REDIRECT_URI=http://localhost:3000/auth/callback
```

`PRIVATE_KEY_PATH` and `PUBLIC_KEY_PATH` are set programmatically by `scripts/setup.js` and do not need to be in `.env` unless you want to override key locations.

## Deployment

Runs behind Nginx + Tailscale Funnel on a Raspberry Pi. OAuth and JWKS endpoints are at root paths (`/authorize`, `/token`, `/.well-known/`) because Claude.ai and OAuth specs require them unprefixed. The account-manager UI is at `/account-manager/`. Nginx config and systemd unit are written by `setup-pi.sh` in the gamebacklog repo.

## Relation to gamebacklog

- gamebacklog redirects to `/authorize` here for login (PKCE flow)
- gamebacklog verifies RS256 `gamebacklog`-audience tokens using the public key from `/.well-known/jwks.json`
- gamebacklog's MCP server verifies `mcp`-audience tokens the same way
- No shared database — account-manager owns all auth state
