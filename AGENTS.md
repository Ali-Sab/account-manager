# account-manager — agent reference

This is the auth service for a personal homelab stack. It issues RS256 JWTs and runs the OAuth 2.0 server that other services use for login. Read CLAUDE.md for full context.

## Key facts for automated tasks

- **Entry point**: `server/index.js` (listen) → `server/app.js` (Express)
- **All signing/verification**: `server/lib/crypto.js` — do not inline JWT logic elsewhere
- **Key material**: loaded lazily by `server/lib/keys.js`; keys live in `DATA_DIR/keys/`
- **DB access**: all through `server/db.js` exports — do not write raw SQL outside that file
- **Setup is idempotent**: `npm run setup` can be re-run safely at any time

## Route map

| Method | Path | File | Auth required |
|--------|------|------|--------------|
| POST | /api/auth/login | routes/auth.js | no |
| POST | /api/auth/mfa | routes/auth.js | mfaToken (body) |
| POST | /api/auth/recovery | routes/auth.js | mfaToken (body) |
| POST | /api/auth/refresh | routes/auth.js | refreshToken cookie + CSRF |
| POST | /api/auth/logout | routes/auth.js | CSRF |
| POST | /api/auth/change-password | routes/auth.js | Bearer (account-manager aud) |
| POST | /api/auth/recovery-codes/regenerate | routes/auth.js | Bearer |
| GET | /api/auth/recovery-codes/count | routes/auth.js | Bearer |
| GET | /api/auth/csrf | routes/auth.js | no |
| GET/POST | /authorize | routes/oauth.js | no (shows login form) |
| GET/POST | /token | routes/oauth.js | client credentials |
| GET | /.well-known/oauth-authorization-server | routes/oauth.js | no |
| GET | /.well-known/oauth-protected-resource | routes/oauth.js | no |
| GET | /.well-known/jwks.json | routes/jwks.js | no |
| GET/POST | /api/setup/* | routes/setup.js | setup_state gate |
| GET/POST | /api/webauthn/* | routes/webauthn.js | varies |

## Adding a new relying party

1. Add an entry to `SERVICES` in `setup-pi.sh` (gamebacklog repo) for routing
2. In `scripts/setup.js`, add a `getOAuthClient` / `upsertOAuthClient` block for the new client with the appropriate `audience` value
3. Re-run `npm run setup` — credentials printed to stdout on first creation
4. In the new service, verify tokens with RS256 public key from `/.well-known/jwks.json`, checking the correct `audience` claim

## Token audiences

- `account-manager` — for the account-manager React UI only
- `gamebacklog` — for the game backlog API
- `mcp` — for Claude.ai MCP access (30-day expiry)
- Add new audiences as new services are onboarded

## What lives here vs. in relying parties

| Concern | Here | Relying party |
|---|---|---|
| Password storage | ✓ | — |
| TOTP secrets | ✓ | — |
| Passkeys | ✓ | — |
| Session (refresh token) | ✓ | — |
| OAuth client registry | ✓ | — |
| RSA private key | ✓ | — |
| RSA public key | ✓ (source) | copy or fetch via JWKS |
| Access token verification | — | ✓ (local RS256 check) |
| Game/app data | — | ✓ |
