# account-manager

Central SSO service for the homelab. Handles login, registration, passkeys (WebAuthn), MFA (TOTP), OAuth 2.0 authorization, JWT issuance, token refresh, and account management. Supports multiple user accounts with an admin invite flow.

All other services are OAuth relying parties — they redirect here for login and verify RS256 JWTs locally. account-manager is the only service that ever touches the private key.

---

## Repo layout

```
account-manager/
  cmd/server/main.go        — process entry point
  internal/
    auth/                   — JWT signing/verification, TOTP, password hashing
    config/                 — env var loading
    db/                     — SQLite schema, migrations, queries
    handler/                — HTTP handlers (auth, oauth, webauthn, setup, admin)
    keys/                   — RSA keypair generation and loading
    mailer/                 — SMTP email sending
    middleware/             — JWT auth, rate limiting, CSRF
    setup/                  — idempotent first-run init (keys, OAuth client seeding)
  src/                      — React CSR app (Vite)
    screens/
      SetupScreen.tsx       — first-run wizard
      LoginScreen.tsx       — password + TOTP login, forgot password flow
      AccountScreen.tsx     — passkey management, email, change password, recovery codes
      InviteScreen.tsx      — new user account creation via invite link
      ResetPasswordScreen.tsx — password reset via emailed link
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Listen port (default: `3001`) |
| `DATA_DIR` | No | Persistent storage path (default: `./data`). Holds SQLite DB and RSA keys. |
| `JWT_ISSUER` | Yes (prod) | Issuer claim in tokens, and the base URL every OAuth discovery endpoint (`authorization_endpoint`, `token_endpoint`, `jwks_uri`, etc.) is built from by literal string concatenation — must exactly match whatever public path prefix your reverse proxy routes to this service. In the homelab-infra deployment that's `https://yourpi.yourtailnet.ts.net/accounts` (note the `/accounts` suffix — nginx proxies `/accounts/*` here). Only omit the path prefix if account-manager is exposed at its own bare origin with no reverse-proxy prefix. |
| `CSRF_SECRET` | Yes (prod) | Random string for CSRF token signing |
| `WEBAUTHN_RP_ID` | Yes (prod) | Relying party ID — the bare hostname, e.g. `yourpi.ts.net` |
| `WEBAUTHN_RP_NAME` | No | Human-readable name shown in passkey prompts |
| `SMTP_HOST` | No | SMTP server hostname. Leave blank to disable password reset emails. |
| `SMTP_PORT` | No | SMTP port (default: `587`) |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASS` | No | SMTP password |
| `SMTP_FROM` | No | From address for outbound email (defaults to `SMTP_USER` if blank) |
| `SMTP_TLS` | No | TLS mode: `starttls` (default, port 587), `tls` (implicit/port 465), `none` (dev only) |
| `RATE_LIMIT_MAX` | No | Max auth requests per IP per 15-minute window (default: `20`). Raise in dev/CI to avoid spurious 429s. |

---

## First-time setup

```bash
go build ./...
go run ./cmd/server
```

On first run the server:

1. Generates an RSA-2048 keypair at `DATA_DIR/keys/`
2. Creates the SQLite database and runs all migrations
3. Seeds one OAuth client entry per relying party service, printing the generated `client_id` and `client_secret` to stdout

**The generated secrets are printed once only.** Copy them into the corresponding env files before the process exits.

Then visit `/accounts/` to complete the setup wizard (username, optional email, password, TOTP).

**Account rules:**
- Usernames: letters, numbers, `_`, `-`, 1–32 characters
- Passwords: minimum 12 characters
- Email: optional everywhere; required only for password reset. Must be a valid `user@domain.tld` format.

---

## Account management

Users can manage their own account from **Account Settings** (the React SPA):

- Change password (requires current password)
- Add / remove passkeys (WebAuthn)
- Set or update email address
- Regenerate TOTP recovery codes
- **Delete account** — permanently removes the account and all associated sessions, passkeys, and OAuth tokens. Requires password confirmation. This cannot be undone.

Admins can delete other users via `DELETE /api/admin/users/:username`. This also clears all their sessions, passkeys, OAuth tokens, and pending reset tokens.

---

## Password reset (SMTP)

Password reset emails require an outbound SMTP server. The simplest free option is a Gmail App Password:

1. Enable 2-Step Verification on your Google account if not already on
2. Go to **myaccount.google.com/apppasswords** and create a new app password
3. Set in your env:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=xxxx xxxx xxxx xxxx
SMTP_FROM=you@gmail.com
```

If `SMTP_HOST` is not set, the forgot-password endpoint still returns success but no email is sent — the feature is silently disabled.

Users must have an email address set on their account (configurable in Account Settings) for the reset flow to work. Email addresses are optional; accounts without one simply can't use password reset.

Reset links expire after 1 hour. If the reset form is submitted with an invalid password or wrong TOTP code, the link remains valid and the user can try again — it is only consumed on success.

---

## Development

```bash
# Backend (rebuilds on change with Air, or just run directly)
go run ./cmd/server

# Frontend
npm run dev    # Vite dev server on :5174, proxies API to :3001
npm run build  # builds React → dist/
```

Tests:

```bash
go test ./...         # unit + integration tests
npm run test:e2e      # Playwright e2e — spins up the Go server automatically
```

---

## Token design

Tokens are RS256 JWTs signed with `DATA_DIR/keys/private.pem`.

| Audience | Issued to | Expiry | Verified by |
|---|---|---|---|
| `account-manager` | account-manager React SPA | 1 h | account-manager |
| `gamebacklog` | game-backlog service | 1 h | game-backlog |
| `service-manager` | service-manager | 1 h | service-manager |
| `chore-chart` | chore-chart | 1 h | chore-chart |
| `mcp` | Claude.ai via MCP connector | 30 d | game-backlog MCP server |

The public key is exposed at `GET /.well-known/jwks.json`. Relying parties fetch it at startup or via the `ACCOUNT_MANAGER_PUBLIC_KEY` env var (PEM contents of `data/keys/public.pem`).

---

## OAuth 2.0 endpoints

| Endpoint | Description |
|---|---|
| `GET /authorize` | Authorization endpoint — shows consent form or auto-approves via session cookie |
| `POST /authorize` | Processes form submission |
| `POST /token` | Token endpoint — auth code or refresh token grant |
| `GET /.well-known/jwks.json` | Public key as JWKS |
| `GET /.well-known/oauth-authorization-server` | Discovery document |

Supports PKCE (`code_challenge_method=S256`) and `client_secret_post` at the token endpoint.

---

## Deployment

Deployed via the infra repo's `deploy.sh`. `DATA_DIR` must be a persistent Docker volume — the RSA keypair and SQLite database live there. If the volume is wiped, all OAuth tokens become invalid and all registered passkeys break.

See [homelab-infra/README.md](../homelab-infra/README.md) for the full deployment guide.
