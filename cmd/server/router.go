package main

import (
	"io/fs"
	"net/http"
	"os"

	"account-manager/internal/config"
	"account-manager/internal/handler"
	"account-manager/internal/middleware"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// newRouter wires all routes and sets app.Limits. Each call makes new limiters.
func newRouter(app *handler.App, cfg *config.Config) http.Handler {
	// ─── Rate limiters ────────────────────────────────────────────────────────
	signInLimiter := middleware.NewRateLimiter(cfg.RateLimitMax, middleware.LimitWindow)
	refreshLimiter := middleware.NewRateLimiter(cfg.RateLimitMax, middleware.LimitWindow)
	setupLimiter := middleware.NewRateLimiter(cfg.RateLimitMax, middleware.LimitWindow)
	app.Limits = &handler.Limits{
		ClientAuthFailures:   middleware.NewRateLimiter(cfg.RateLimitMax, middleware.LimitWindow),
		SecondFactorFailures: middleware.NewRateLimiter(secondFactorMax(cfg.RateLimitMax), middleware.LimitWindow),
	}

	// ─── Middleware factories ─────────────────────────────────────────────────
	requireAuth := middleware.RequireAuth(app.Keys.Public, cfg.JWTIssuer)
	csrfProtect := middleware.DoubleCsrfProtection(cfg.CsrfSecret)

	// ─── Router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(middleware.ClientIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)

	// ── OAuth & discovery routes (root-level) ────────────────────────────────
	// Discovery endpoints are public and cross-origin readable.
	r.With(handler.DiscoveryCORS).Get("/.well-known/jwks.json", app.JWKS)
	r.With(handler.DiscoveryCORS).Get("/.well-known/oauth-authorization-server", app.OAuthAuthorizationServer)
	// RFC 8414 §3.1: when the issuer has a path component (ours does — JWT_ISSUER
	// ends in /accounts), spec-compliant clients insert the well-known suffix
	// *before* that path, e.g. /.well-known/oauth-authorization-server/accounts,
	// rather than requesting the bare path above. The handler ignores any suffix
	// and returns the same static metadata either way.
	r.With(handler.DiscoveryCORS).Get("/.well-known/oauth-authorization-server/*", app.OAuthAuthorizationServer)
	r.With(handler.DiscoveryCORS).Get("/.well-known/oauth-protected-resource", app.OAuthProtectedResource)
	r.With(handler.DiscoveryCORS).Get("/.well-known/oauth-protected-resource/*", app.OAuthProtectedResource)
	// Authorize: browser navigation only — no CORS needed. POST is CSRF-protected.
	r.Get("/logout", app.LogoutGET)
	r.Get("/authorize", app.AuthorizeGET)
	r.With(signInLimiter.Middleware, csrfProtect).Post("/authorize", app.AuthorizePOST)
	r.Get("/oauth/authorize", app.AuthorizeGET)
	r.With(signInLimiter.Middleware, csrfProtect).Post("/oauth/authorize", app.AuthorizePOST)
	// Token: server-to-server only, no CORS. Failed client logins are limited in the handler.
	r.Get("/token", app.TokenGET)
	r.Post("/token", app.TokenPOST)
	r.Get("/oauth/token", app.TokenGET)
	r.Post("/oauth/token", app.TokenPOST)

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
		r.With(signInLimiter.Middleware).Post("/auth/login", app.Login)
		r.With(signInLimiter.Middleware).Post("/auth/mfa", app.MFA)
		r.With(signInLimiter.Middleware).Post("/auth/recovery", app.Recovery)
		r.With(refreshLimiter.Middleware).With(csrfProtect).Post("/auth/refresh", app.Refresh)
		r.With(csrfProtect).Post("/auth/logout", app.Logout)
		r.With(requireAuth).Get("/auth/me", app.Me)
		r.With(requireAuth).Delete("/auth/account", app.DeleteAccount)
		r.With(requireAuth).Post("/auth/change-password", app.ChangePassword)
		r.With(requireAuth).Post("/auth/recovery-codes/regenerate", app.RegenerateRecoveryCodes)
		r.With(requireAuth).Get("/auth/recovery-codes/count", app.RecoveryCodeCount)
		r.With(requireAuth).Put("/auth/email", app.UpdateEmail)
		r.With(requireAuth).Get("/auth/email/pending", app.PendingEmail)
		r.With(requireAuth, csrfProtect).Delete("/auth/email/pending", app.CancelPendingEmail)
		r.With(signInLimiter.Middleware).Get("/auth/email/verify", app.VerifyEmail)
		r.With(signInLimiter.Middleware).Post("/auth/forgot-password", app.ForgotPassword)
		r.With(signInLimiter.Middleware).Post("/auth/reset-password", app.ResetPassword)

		// WebAuthn
		r.With(signInLimiter.Middleware).Post("/webauthn/register/start", app.WebAuthnRegisterStart)
		r.With(signInLimiter.Middleware).Post("/webauthn/register/finish", app.WebAuthnRegisterFinish)
		r.With(requireAuth).Post("/webauthn/add-device/start", app.WebAuthnAddDeviceStart)
		r.With(requireAuth).Post("/webauthn/add-device/finish", app.WebAuthnAddDeviceFinish)
		r.With(signInLimiter.Middleware).Post("/webauthn/login/start", app.WebAuthnLoginStart)
		r.With(signInLimiter.Middleware).Post("/webauthn/login/finish", app.WebAuthnLoginFinish)
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

	return r
}

// secondFactorMax is the per-account budget for wrong TOTP, recovery and reset
// codes: half the per-address budget, at least 1.
func secondFactorMax(rateLimitMax int) int {
	if n := rateLimitMax / 2; n > 0 {
		return n
	}
	return 1
}
