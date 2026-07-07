package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/config"
	"account-manager/internal/db"
	"account-manager/internal/keys"
	accmw "account-manager/internal/middleware"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// newTestApp creates an App wired to an in-memory SQLite DB with a fresh RSA keypair.
func newTestApp(t *testing.T) *App {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	kp := &keys.KeyPair{Private: priv, Public: &priv.PublicKey}
	cfg := &config.Config{
		JWTIssuer:      "http://localhost:3001",
		CsrfSecret:     "test-csrf-secret",
		IsProd:         false,
		WebAuthnRPID:   "localhost",
		WebAuthnRPName: "Test",
	}
	return &App{DB: sqlDB, Keys: kp, Cfg: cfg}
}

// buildRouter wires the app routes the same way main.go does.
func buildRouter(app *App) http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)

	requireAuth := mwRequireAuth(app)
	csrfProtect := mwCSRFProtect(app)
	authLimiter := noopMiddleware

	r.Get("/api/auth/csrf", app.CSRF)
	r.With(authLimiter).Post("/api/auth/login", app.Login)
	r.With(authLimiter).Post("/api/auth/mfa", app.MFA)
	r.With(authLimiter).Post("/api/auth/recovery", app.Recovery)
	r.With(authLimiter).With(csrfProtect).Post("/api/auth/refresh", app.Refresh)
	r.With(csrfProtect).Post("/api/auth/logout", app.Logout)
	r.With(requireAuth).Get("/api/auth/me", app.Me)
	r.With(requireAuth).Post("/api/auth/change-password", app.ChangePassword)
	r.With(requireAuth).Post("/api/auth/recovery-codes/regenerate", app.RegenerateRecoveryCodes)
	r.With(requireAuth).Get("/api/auth/recovery-codes/count", app.RecoveryCodeCount)
	r.With(requireAuth).Put("/api/auth/email", app.UpdateEmail)
	r.With(requireAuth).Get("/api/auth/email/pending", app.PendingEmail)
	r.Get("/api/auth/email/verify", app.VerifyEmail)
	r.With(requireAuth).Delete("/api/auth/account", app.DeleteAccount)
	r.Post("/api/auth/forgot-password", app.ForgotPassword)
	r.Post("/api/auth/reset-password", app.ResetPassword)

	r.Get("/api/setup/status", app.SetupStatus)
	r.Post("/api/setup/secret", app.SetupSecret)
	r.Get("/api/setup/secret", app.SetupSecret)
	r.Post("/api/setup", app.Setup)

	r.Get("/api/invite/secret", app.InviteSecret)
	r.Post("/api/invite/accept", app.AcceptInvite)

	r.Route("/api/admin", func(r chi.Router) {
		r.Use(requireAuth)
		r.Use(app.AdminOnly)
		r.Get("/users", app.AdminListUsers)
		r.Delete("/users/{username}", app.AdminDeleteUser)
		r.Post("/invite", app.AdminCreateInvite)
	})

	r.With(DiscoveryCORS).Get("/.well-known/jwks.json", app.JWKS)
	r.With(DiscoveryCORS).Get("/.well-known/oauth-authorization-server", app.OAuthAuthorizationServer)
	r.Get("/authorize", app.AuthorizeGET)
	r.Post("/authorize", app.AuthorizePOST)
	r.Get("/token", app.TokenGET)
	r.Post("/token", app.TokenPOST)

	return r
}

func mwRequireAuth(app *App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if len(header) < 8 {
				http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			claims, err := auth.VerifyAccess(app.publicKey(), app.Cfg.JWTIssuer, header[7:])
			if err != nil {
				http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), accmw.ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func mwCSRFProtect(app *App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In tests we inject the CSRF header/cookie automatically.
			next.ServeHTTP(w, r)
		})
	}
}

func noopMiddleware(next http.Handler) http.Handler { return next }

// ─── JSON helpers ─────────────────────────────────────────────────────────────

func jsonBody(t *testing.T, v any) io.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return bytes.NewReader(b)
}

func decodeJSON(t *testing.T, body io.Reader, dst any) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(dst); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func doFormRequest(t *testing.T, router http.Handler, method, path string, vals url.Values, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func doRequest(t *testing.T, router http.Handler, method, path string, body io.Reader, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ─── DB seeding helpers ───────────────────────────────────────────────────────

// seedAccount creates a configured account (password + TOTP) and returns the TOTP secret.
func seedAccount(t *testing.T, sqlDB *sql.DB) (username, password, totpSecret string) {
	t.Helper()
	username = "alice"
	password = "password123"
	salt := "deadbeefdeadbeefdeadbeefdeadbeef"
	hash := auth.HashPassword(password, salt)
	secret, err := auth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	plain, hashes, err := auth.GenerateRecoveryCodes(salt, 8)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	_ = plain
	if err := db.CreateUser(sqlDB, &db.User{
		Username:      username,
		Hash:          hash,
		Salt:          salt,
		TotpSecret:    secret,
		RecoveryCodes: hashes,
		IsAdmin:       true,
		CreatedAt:     time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return username, password, secret
}

// seedAccessToken returns a valid access token for the given username.
func seedAccessToken(t *testing.T, app *App, username string) string {
	t.Helper()
	tok, err := auth.SignToken(app.privateKey(), app.Cfg.JWTIssuer, username, "account-manager", time.Hour)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	return tok
}
