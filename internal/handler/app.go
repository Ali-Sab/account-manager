package handler

import (
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"account-manager/internal/auth"
	"account-manager/internal/config"
	"account-manager/internal/keys"
	"account-manager/internal/middleware"
)

var (
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)
	emailRe    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// validUsername returns an error message if the username is invalid, empty string otherwise.
func validUsername(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return "Username required"
	}
	if !usernameRe.MatchString(u) {
		return "Username may only contain letters, numbers, underscores, and hyphens (max 32 chars)"
	}
	return ""
}

// validEmail returns an error message if a non-empty email has an invalid format.
func validEmail(e string) string {
	e = strings.TrimSpace(e)
	if e == "" {
		return "" // email is optional everywhere it's used
	}
	if !emailRe.MatchString(e) {
		return "Invalid email address"
	}
	return ""
}

// App holds shared dependencies injected into all handlers.
type App struct {
	DB      *sql.DB
	Keys    *keys.KeyPair
	Cfg     *config.Config
}

// helpers

func (a *App) privateKey() *rsa.PrivateKey { return a.Keys.Private }
func (a *App) publicKey() *rsa.PublicKey   { return a.Keys.Public }

func usernameFromContext(r *http.Request) string {
	claims, _ := r.Context().Value(middleware.ClaimsKey).(*auth.Claims)
	if claims == nil {
		return ""
	}
	return claims.Subject
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
