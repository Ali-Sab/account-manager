# ── Stage 1: build the Go server binary ──────────────────────────────────────
FROM golang:1.26-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o account-manager-bin ./cmd/server

# ── Stage 2: Playwright test runner ───────────────────────────────────────────
# Official Playwright image ships with Chromium and all browser dependencies.
FROM mcr.microsoft.com/playwright:v1.60.0-jammy
WORKDIR /app

# sqlite3 is required by the queryDB helper in e2e/helpers.ts.
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# Pre-built server binary — no Go toolchain needed at runtime.
COPY --from=go-builder /app/account-manager-bin ./account-manager-bin

# npm deps first (better layer caching).
COPY package*.json ./
RUN npm ci

# Test files only — src/ and dist/ are not needed for API-level tests.
COPY e2e/ ./e2e/

# Tell global-setup to run the binary directly instead of "go run ./cmd/server".
ENV E2E_SERVER_BIN=/app/account-manager-bin

CMD ["npm", "run", "test:e2e"]
