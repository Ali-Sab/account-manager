# account-manager

Standalone auth service and account portal. Go backend (chi + modernc SQLite) + React CSR frontend (Vite). Other services are relying parties — they redirect here for login and verify the RS256 JWTs it issues.

## Repo layout

```
cmd/server/main.go        — entry point: idempotent setup, start HTTP server
internal/
  config/config.go        — env vars + defaults
  db/
    db.go                 — open SQLite (modernc, no CGO), run migrations
    queries.go            — all CRUD: users, refresh tokens, passkeys, OAuth tables
  keys/keys.go            — load/generate RSA keypair; JWKS builder
  auth/
    jwt.go                — SignToken, VerifyAccess, SignMFAToken, VerifyMFAToken (RS256)
    password.go           — PBKDF2-SHA512, 310000 iters, 64-byte key, hex output
    totp.go               — GenerateSecret, VerifyTOTP (±1 period)
    recovery.go           — GenerateRecoveryCodes (8 codes, xxxx-xxxx-xx format)
  middleware/
    auth.go               — RequireAuth: Bearer JWT check, audience=account-manager
    csrf.go               — double-submit CSRF cookie
    ratelimit.go          — in-memory sliding-window rate limiter
  handler/
    auth.go               — /api/auth/* routes
    setup.go              — /api/setup/* routes + QR code
    webauthn.go           — /api/webauthn/* routes (go-webauthn/webauthn)
    oauth.go              — /authorize, /token, /.well-known/oauth-* (PKCE)
    jwks.go               — GET /.well-known/jwks.json
  setup/setup.go          — idempotent init: RSA key gen, DB migrations, OAuth client seeding
src/                      — React CSR app
  screens/
    SetupScreen.tsx         — first-run wizard
    LoginScreen.tsx         — password + TOTP login, forgot password
    AccountScreen.tsx       — passkey management, email, change password, recovery codes
    InviteScreen.tsx        — new user account creation via invite link
    ResetPasswordScreen.tsx — password reset via emailed link
  context/AuthContext.tsx — boots via POST /api/auth/refresh
e2e/                      — Playwright e2e tests
```

## Startup

```bash
# Dev: Go server + Vite in parallel
npm run dev

# Production build (React only — Go binary built separately)
npm run build
CGO_ENABLED=0 go build -o account-manager ./cmd/server
./account-manager        # runs setup + starts server
```

The binary runs setup automatically on first start: generates RSA keys, runs migrations, seeds OAuth clients. Generated client credentials are printed to stdout once.

## Token design

All tokens are RS256 JWTs signed with the private key in `DATA_DIR/keys/private.pem`.

| Audience | Issued to | Expiry | Used by |
|---|---|---|---|
| `account-manager` | account-manager React SPA | 1h | account-manager UI routes |
| `gamebacklog` | game backlog app (via PKCE flow) | 1h | gamebacklog API |
| `mcp` | Claude.ai (via MCP OAuth flow) | 30d | MCP server in gamebacklog |

`auth.SignToken(priv, issuer, sub, audience, duration)` is the single signing function. Relying parties verify locally using the public key from `/.well-known/jwks.json` — no round-trip needed.

## OAuth clients

Two well-known clients are seeded at first startup via `internal/setup/setup.go`:

- `claude-mcp` — Claude.ai's MCP connector. Audience `mcp`.
- `gamebacklog-web` — game backlog PKCE login flow. Audience `gamebacklog`.

Client credentials are auto-generated and stored hashed in SQLite. The plaintext secret is only printed once at first startup. To rotate: delete the row from `oauth_clients` and restart.

The `/authorize` endpoint skips the consent page for already-authenticated users (valid `refreshToken` cookie).

## Login flow (account-manager UI)

1. `POST /api/auth/login` — PBKDF2 password check → returns short-lived `mfaToken` (RS256, 5m, `mfaPending: true`)
2. `POST /api/auth/mfa` — TOTP check → sets `refreshToken` httpOnly cookie (30d), returns `accessToken` (1h)
3. On subsequent loads: `POST /api/auth/refresh` (CSRF-protected) → returns fresh `accessToken`

## Validation rules

- **Usernames**: `[a-zA-Z0-9_-]`, 1–32 characters. Enforced at setup, invite accept, and (via WebAuthn) passkey registration.
- **Passwords**: minimum 12 characters. Enforced at setup, invite accept, change-password, reset-password, and WebAuthn passkey setup.
- **Email**: optional everywhere. When provided, must match `user@domain.tld` format.

## Database (SQLite)

Auth tables only — no game data. Tables: `users`, `refresh_tokens`, `passkey_credentials`, `webauthn_challenges`, `setup_state`, `pending_setup`, `oauth_clients`, `oauth_auth_codes`, `oauth_refresh_tokens`, `pending_invites`, `password_reset_tokens`.

DB file: `DATA_DIR/account-manager.db` (default: `./data/account-manager.db`).

Uses `modernc.org/sqlite` (pure Go, no CGO) — no C toolchain needed.

## SMTP / email

Password reset emails require SMTP. Three TLS modes via `SMTP_TLS`:

| Mode | Port | Use |
|------|------|-----|
| `starttls` (default) | 587 | Standard submission, upgrades to TLS |
| `tls` | 465 | Implicit TLS (SMTPS) |
| `none` | any | Dev only — no encryption |

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

## Testing

```bash
go test ./...            # unit + integration tests
npm run test:e2e         # Playwright e2e (requires Go binary + npm run build)
```

## Deployment

Runs behind Nginx + Tailscale Funnel on a Raspberry Pi. OAuth and JWKS endpoints are at root paths (`/authorize`, `/token`, `/.well-known/`) because Claude.ai and OAuth specs require them unprefixed. The account-manager UI is at `/account-manager/`. Nginx config and systemd unit are written by `setup-pi.sh` in the gamebacklog repo.

## Relation to gamebacklog

- gamebacklog redirects to `/authorize` here for login (PKCE flow)
- gamebacklog verifies RS256 `gamebacklog`-audience tokens using the public key from `/.well-known/jwks.json`
- gamebacklog's MCP server verifies `mcp`-audience tokens the same way
- No shared database — account-manager owns all auth state
