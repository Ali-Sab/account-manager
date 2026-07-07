# E2E Testing Approaches

Summary of approaches considered and tried for running the account-manager Playwright test suite in a Docker-based homelab environment.

---

## Approaches

| # | Approach | Status | Recommended? |
|---|---|---|---|
| 1 | Local — `npm run test:e2e` | ✅ Works | For development |
| 2 | e2e container → production account-manager | ❌ Failed | No |
| 3 | e2e container → production account-manager + configurable credentials | ⚠️ Partially works | No |
| 4 | Expose port + run locally against Docker | 💬 Discussed, not built | Maybe |
| 5 | Self-contained e2e container (own server + DB) | ✅ Works | **Yes — for `make test`** |

---

## Approach 1 — Local `npm run test:e2e`

`global-setup.ts` runs `go run ./cmd/server` in a temp dir, Playwright hits `localhost:4001`.

**Pros**
- Zero setup — works out of the box on any dev machine with Go + Node
- Fast iteration (no Docker build)
- Full sqlite3 access for `queryDB`
- Fresh DB every run — tests are fully isolated

**Cons**
- Requires Go toolchain installed locally
- Not runnable from homelab-infra
- Slow first run (`go run` compiles the server)

---

## Approach 2 — e2e container pointing at production account-manager

The e2e container joins the `internal` Docker network and hits `http://account-manager:3001` directly with `E2E_BASE_URL`.

**What failed**
- Tests assume `alice` / `password1234` — the production admin account has different credentials
- OAuth tests assume `gamebacklog-web` is registered with `http://localhost:3000/auth/callback` — production has a different redirect URI
- Production `RATE_LIMIT_MAX=60` gets hit across 25 tests
- `queryDB` writes (`UPDATE users SET email`) touch the live database
- Test users (bob, charlie, dave, pwrtest) accumulate in the production DB

**Pros**
- Tests the actual running service

**Cons**
- Tests require known admin credentials that match the production account
- Pollutes the production DB with test users
- OAuth client configuration must match test expectations
- Rate limits may cause flaky failures
- Fundamentally incompatible with what the tests assume (fresh DB, known state)

---

## Approach 3 — Production account-manager + configurable credentials

Extended approach 2 with `E2E_ADMIN_USERNAME`, `E2E_ADMIN_PASSWORD`, `E2E_GAMEBACKLOG_REDIRECT_URI` env vars, `setup-e2e` make target to auto-detect the username from the DB and prompt for password.

**What works**
- Username auto-detected from the volume-mounted SQLite DB
- Redirect URI read from DB when not explicitly set
- `env/e2e.env` pattern keeps credentials out of git

**What still doesn't work**
- DB still polluted by test users
- `queryDB` writes still touch production data
- Tests designed around fresh-DB assumptions (e.g. "recovery code count returns 8") are flaky on repeat runs
- Password reset tests change the admin password — second run fails

**Pros**
- Tests run against the real service
- Could detect real regressions in the running stack

**Cons**
- Complex credential management
- Not idempotent — state leaks between runs
- Password reset tests must use a throwaway user (added `pwrtest`) to avoid changing admin password
- Still requires `make setup-e2e` one-time step
- Fundamentally fighting the test design

---

## Approach 4 — Expose port + run tests locally

Add a `ports: ["3001:3001"]` mapping to account-manager in `docker-compose.override.yml`, then run `E2E_BASE_URL=http://localhost:3001 npm run test:e2e` on the host.

**Not built.** Same fundamental problems as approaches 2 & 3 (production DB, credentials), plus:
- `queryDB` can't reach the Docker volume from the Mac host (it lives inside the Docker Linux VM)
- Would need `queryDB` to shell out through Docker (`docker compose exec` or a temp container)

**Pros**
- No Docker image to build for tests
- Fast feedback loop

**Cons**
- All the same state-pollution problems as approach 2
- `queryDB` requires workaround for volume access on Mac

---

## Approach 5 — Self-contained e2e container ✅ Recommended

The `e2e/Dockerfile` is a two-stage build:
1. Go builder — compiles the account-manager binary
2. Playwright image — installs sqlite3, npm deps, copies the binary and test files

`global-setup.ts` detects `E2E_SERVER_BIN=/app/account-manager-bin` and spawns the binary (instead of `go run`) into a fresh temp directory. Tests run against `localhost:4001` inside the container. `global-teardown.ts` kills the server and deletes the temp dir.

```
make test-e2e-account-manager
# expands to: docker compose --profile e2e run --rm --build e2e
```

**Pros**
- Zero credential configuration — alice/password1234 is always the admin (fresh DB)
- Fully isolated — no production data touched
- Idempotent — identical results every run
- Runnable from homelab-infra with one command
- sqlite3 available inside container, DB path accessible
- Binary is pre-compiled — server starts in <1s vs `go run`'s compile time

**Cons**
- Docker image build takes ~2 min on first run (Go compile + Playwright download); cached after that
- Image is large (~1 GB) — Go build cache + Playwright Chromium
- Does not test the actual running production service (it's a separate binary)
- Two things to keep in sync: the binary baked into the image vs the running service (mitigated by `--build` in the make target, which rebuilds from the same source)

---

## Current state

- **Development**: `npm run test:e2e` (local, approach 1)
- **CI / homelab**: `make test-e2e-account-manager` (approach 5)
- `E2E_BASE_URL`, `E2E_ADMIN_USERNAME`, `E2E_ADMIN_PASSWORD`, and `getGamebacklogRedirectUri()` remain in the code in case approach 3 is ever revisited

---

## Why the tests need a fresh DB

The suite makes assumptions that only hold on a server that was just initialized:

- `apiSetup` creates `alice` with `password1234` and a known TOTP secret
- `apiCreateUser` creates named test users (`bob`, `charlie`, `dave`, `pwrtest`) — these conflict on repeat runs against a persistent DB
- `account.spec.ts` asserts recovery code count is exactly 8
- `password-reset.spec.ts` changes the test user's password multiple times
- `queryDB` writes directly to SQLite (`UPDATE users SET email = ...`)

A persistent production DB can't satisfy these constraints without either resetting between runs or rewriting the tests to be fully stateless — which would significantly increase their complexity.
