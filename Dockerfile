# Stage 1: build React frontend
FROM node:20-alpine AS frontend
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# Stage 2: build Go binary (CGO_ENABLED=0 — pure Go sqlite, no C toolchain needed)
FROM golang:1.26-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o account-manager ./cmd/server

# Stage 3: minimal runtime
# alpine:3.20 (~8 MB) rather than scratch because SQLite WAL mode needs /tmp.
# Total image ~30-40 MB vs ~300 MB for the previous Node.js image.
FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY --from=go-builder /app/account-manager .
COPY --from=frontend   /app/dist ./dist
EXPOSE 3001
# DATA_DIR must be a mounted volume so RSA keys and the SQLite DB persist across restarts.
CMD ["/app/account-manager"]
