package main

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"

	"account-manager/internal/config"
	"account-manager/internal/db"
	"account-manager/internal/handler"
	"account-manager/internal/middleware"
	"account-manager/internal/setup"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

func main() {
	// Load .env if present (ignored in production where vars are set directly).
	_ = godotenv.Load()

	cfg := config.Load()

	// Open DB (runs migrations).
	sqlDB, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	// Run idempotent setup: key gen + OAuth client seeding.
	kp, err := setup.EnsureInitialized(cfg.DataDir,
		setup.ClientURIs{RedirectURI: cfg.GamebacklogRedirect, BackchannelURI: cfg.GamebacklogBackchannelURI},
		setup.ClientURIs{RedirectURI: cfg.ServiceManagerRedirect, BackchannelURI: cfg.ServiceManagerBackchannelURI},
		setup.ClientURIs{RedirectURI: cfg.ChoreChartRedirect, BackchannelURI: cfg.ChoreChartBackchannelURI},
		sqlDB,
	)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	app := &handler.App{DB: sqlDB, Keys: kp, Cfg: cfg}

	// ─── Rate limiters ────────────────────────────────────────────────────────
	authLimiter  := middleware.NewRateLimiter(cfg.RateLimitMax, 15*time.Minute)
	setupLimiter := middleware.NewRateLimiter(cfg.RateLimitMax, 15*time.Minute)

	// ─── Middleware factories ─────────────────────────────────────────────────
	requireAuth   := middleware.RequireAuth(kp.Public, cfg.JWTIssuer)
	csrfProtect   := middleware.DoubleCsrfProtection(cfg.CsrfSecret)

	// ─── Router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)

	// ── OAuth & discovery routes (root-level) ────────────────────────────────
	// Discovery endpoints are public and cross-origin readable.
	r.With(handler.DiscoveryCORS).Get("/.well-known/jwks.json", app.JWKS)
	r.With(handler.DiscoveryCORS).Get("/.well-known/oauth-authorization-server", app.OAuthAuthorizationServer)
	r.With(handler.DiscoveryCORS).Get("/.well-known/oauth-protected-resource", app.OAuthProtectedResource)
	r.With(handler.DiscoveryCORS).Get("/.well-known/oauth-protected-resource/*", app.OAuthProtectedResource)
	// Authorize: browser navigation only — no CORS needed. POST is CSRF-protected.
	r.Get("/logout", app.LogoutGET)
	r.Get("/authorize", app.AuthorizeGET)
	r.With(authLimiter.Middleware, csrfProtect).Post("/authorize", app.AuthorizePOST)
	r.Get("/oauth/authorize", app.AuthorizeGET)
	r.With(authLimiter.Middleware, csrfProtect).Post("/oauth/authorize", app.AuthorizePOST)
	// Token: server-to-server only — no CORS, rate-limited.
	r.Get("/token", app.TokenGET)
	r.With(authLimiter.Middleware).Post("/token", app.TokenPOST)
	r.Get("/oauth/token", app.TokenGET)
	r.With(authLimiter.Middleware).Post("/oauth/token", app.TokenPOST)

	// ── API routes ────────────────────────────────────────────────────────────
	r.Route("/api", func(r chi.Router) {
		// Internal service-to-service
		r.Post("/mcp-client", app.MCPClientInfo)

		// Setup (first-run only)
		r.Get("/setup/status", app.SetupStatus)
		r.With(setupLimiter.Middleware).Get("/setup/secret", app.SetupSecret)
		r.With(setupLimiter.Middleware).Post("/setup", app.Setup)

		// Invite (public — token is the auth)
		r.With(setupLimiter.Middleware).Get("/invite/secret", app.InviteSecret)
		r.With(setupLimiter.Middleware).Post("/invite/accept", app.AcceptInvite)

		// Auth
		r.Get("/auth/csrf", app.CSRF)
		r.With(authLimiter.Middleware).Post("/auth/login", app.Login)
		r.With(authLimiter.Middleware).Post("/auth/mfa", app.MFA)
		r.With(authLimiter.Middleware).Post("/auth/recovery", app.Recovery)
		r.With(authLimiter.Middleware).With(csrfProtect).Post("/auth/refresh", app.Refresh)
		r.With(csrfProtect).Post("/auth/logout", app.Logout)
		r.With(requireAuth).Get("/auth/me", app.Me)
		r.With(requireAuth).Delete("/auth/account", app.DeleteAccount)
		r.With(requireAuth).Post("/auth/change-password", app.ChangePassword)
		r.With(requireAuth).Post("/auth/recovery-codes/regenerate", app.RegenerateRecoveryCodes)
		r.With(requireAuth).Get("/auth/recovery-codes/count", app.RecoveryCodeCount)
		r.With(requireAuth).Put("/auth/email", app.UpdateEmail)
		r.With(requireAuth).Get("/auth/email/pending", app.PendingEmail)
		r.With(requireAuth, csrfProtect).Delete("/auth/email/pending", app.CancelPendingEmail)
		r.With(authLimiter.Middleware).Get("/auth/email/verify", app.VerifyEmail)
		r.With(authLimiter.Middleware).Post("/auth/forgot-password", app.ForgotPassword)
		r.With(authLimiter.Middleware).Post("/auth/reset-password", app.ResetPassword)

		// WebAuthn
		r.With(authLimiter.Middleware).Post("/webauthn/register/start", app.WebAuthnRegisterStart)
		r.With(authLimiter.Middleware).Post("/webauthn/register/finish", app.WebAuthnRegisterFinish)
		r.With(requireAuth).Post("/webauthn/add-device/start", app.WebAuthnAddDeviceStart)
		r.With(requireAuth).Post("/webauthn/add-device/finish", app.WebAuthnAddDeviceFinish)
		r.With(authLimiter.Middleware).Post("/webauthn/login/start", app.WebAuthnLoginStart)
		r.With(authLimiter.Middleware).Post("/webauthn/login/finish", app.WebAuthnLoginFinish)
		r.With(requireAuth).Get("/webauthn/credentials", app.WebAuthnCredentials)
		r.With(requireAuth).Delete("/webauthn/credentials/{id}", app.WebAuthnDeleteCredential)

		// Admin (requireAuth + AdminOnly)
		r.Route("/admin", func(r chi.Router) {
			r.Use(requireAuth)
			r.Use(app.AdminOnly)
			r.Get("/users", app.AdminListUsers)
			r.Delete("/users/{username}", app.AdminDeleteUser)
			r.Post("/invite", app.AdminCreateInvite)
		})
	})

	// ── Static files + SPA fallback ───────────────────────────────────────────
	distFS := os.DirFS("dist")
	fileServer := http.FileServer(http.FS(distFS))
	r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
		_, err := fs.Stat(distFS, req.URL.Path[1:])
		if err != nil {
			req.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, req)
	})

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("account-manager listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
