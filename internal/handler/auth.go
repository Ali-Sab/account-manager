package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"
	"account-manager/internal/mailer"
	"account-manager/internal/middleware"
)

// POST /api/auth/login
func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}

	user, _ := db.GetUser(a.DB, body.Username)

	// Always hash to prevent username-enumeration timing attacks.
	salt := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if user != nil {
		salt = user.Salt
	}
	hash := auth.HashPassword(body.Password, salt)
	if user == nil || hash != user.Hash {
		jsonErr(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	mfaToken, err := auth.SignMFAToken(a.privateKey(), a.Cfg.JWTIssuer, user.Username)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Login failed")
		return
	}
	jsonOK(w, map[string]string{"mfaToken": mfaToken})
}

// POST /api/auth/mfa
func (a *App) MFA(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MFAToken string `json:"mfaToken"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}

	claims, err := auth.VerifyMFAToken(a.publicKey(), a.Cfg.JWTIssuer, body.MFAToken)
	if err != nil || claims == nil {
		jsonErr(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	user, _ := db.GetUser(a.DB, claims.Subject)
	if user == nil || !auth.VerifyTOTP(user.TotpSecret, body.Code) {
		jsonErr(w, http.StatusUnauthorized, "Invalid MFA code")
		return
	}

	accessToken, csrfToken, err := a.issueSession(w, r, user.Username)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "MFA failed")
		return
	}
	jsonOK(w, map[string]string{"accessToken": accessToken, "csrfToken": csrfToken})
}

// POST /api/auth/recovery
func (a *App) Recovery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MFAToken string `json:"mfaToken"`
		Code     string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}

	claims, err := auth.VerifyMFAToken(a.publicKey(), a.Cfg.JWTIssuer, body.MFAToken)
	if err != nil {
		jsonErr(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	user, _ := db.GetUser(a.DB, claims.Subject)
	if user == nil || len(user.RecoveryCodes) == 0 {
		jsonErr(w, http.StatusUnauthorized, "No recovery codes available")
		return
	}

	idx, ok := consumeRecoveryCode(user, body.Code)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "Invalid recovery code")
		return
	}

	remaining := user.RecoveryCodes
	remaining = append(remaining[:idx], remaining[idx+1:]...)
	user.RecoveryCodes = remaining
	if err := db.UpdateUser(a.DB, user); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Recovery failed")
		return
	}

	accessToken, csrfToken, err := a.issueSession(w, r, user.Username)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Recovery failed")
		return
	}
	jsonOK(w, map[string]any{
		"accessToken": accessToken,
		"csrfToken":   csrfToken,
		"remaining":   len(remaining),
	})
}

// POST /api/auth/recovery-codes/regenerate  (requireAuth)
func (a *App) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	user, _ := db.GetUser(a.DB, username)
	if user == nil {
		jsonErr(w, http.StatusBadRequest, "Not configured")
		return
	}
	plain, hashes, err := auth.GenerateRecoveryCodes(user.Salt, 8)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to generate codes")
		return
	}
	user.RecoveryCodes = hashes
	if err := db.UpdateUser(a.DB, user); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to save codes")
		return
	}
	jsonOK(w, map[string]any{"recoveryCodes": plain})
}

// GET /api/auth/recovery-codes/count  (requireAuth)
func (a *App) RecoveryCodeCount(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	user, _ := db.GetUser(a.DB, username)
	count := 0
	if user != nil {
		count = len(user.RecoveryCodes)
	}
	jsonOK(w, map[string]int{"remaining": count})
}

// GET /api/auth/csrf
func (a *App) CSRF(w http.ResponseWriter, r *http.Request) {
	token := middleware.GenerateCSRFToken(w, r, a.Cfg.CsrfSecret, a.Cfg.IsProd)
	jsonOK(w, map[string]string{"csrfToken": token})
}

// POST /api/auth/refresh  (CSRF-protected)
func (a *App) Refresh(w http.ResponseWriter, r *http.Request) {
	rt, err := r.Cookie("refreshToken")
	if err != nil {
		jsonErr(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}
	username, valid := db.ValidateRefreshToken(a.DB, rt.Value)
	if !valid {
		jsonErr(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}
	accessToken, err := auth.SignToken(a.privateKey(), a.Cfg.JWTIssuer, username, "account-manager", time.Hour)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Refresh failed")
		return
	}
	jsonOK(w, map[string]string{"accessToken": accessToken})
}

var logoutPageTmpl = template.Must(template.New("logout").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signed out — Account Manager</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; color: #1a1a1a; text-align: center; }
    h1 { font-size: 1.2rem; margin-bottom: 0.4rem; }
    p  { color: #555; margin: 0 0 1.5rem; font-size: 0.95rem; }
    a.btn { display: inline-block; padding: 9px 22px; border-radius: 6px; background: #2563eb; color: #fff; text-decoration: none; font-size: 0.95rem; }
    a.btn:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <h1>You've been signed out</h1>
  <p>Your session has ended.</p>
  {{if .RedirectURI}}<a class="btn" href="{{.RedirectURI}}">Continue</a>{{end}}
</body>
</html>`))

// uriOrigin returns "scheme://host" for a URI, or "" if unparseable.
func uriOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

var backchannelClient = &http.Client{Timeout: 5 * time.Second}

// fireBackchannelLogout signs a logout token and POSTs it to every client app
// that holds an active OAuth refresh token for username. Called after the
// user's own refresh tokens have been looked up but before they are deleted.
func (a *App) fireBackchannelLogout(username string, uris []string) {
	if len(uris) == 0 {
		return
	}
	token, err := auth.SignLogoutToken(a.privateKey(), a.Cfg.JWTIssuer, username)
	if err != nil {
		log.Printf("backchannel logout: sign token: %v", err)
		return
	}
	body := "logout_token=" + url.QueryEscape(token)
	for _, uri := range uris {
		uri := uri
		go func() {
			resp, err := backchannelClient.Post(uri, "application/x-www-form-urlencoded", strings.NewReader(body))
			if err != nil {
				log.Printf("backchannel logout %s: %v", uri, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
				log.Printf("backchannel logout %s: status %d", uri, resp.StatusCode)
			}
		}()
	}
}

// logoutUser revokes the session refresh token, clears all OAuth refresh tokens
// for the user, fires backchannel logout to registered clients, and clears the
// refreshToken cookie. Returns the username (empty string if no session cookie).
func (a *App) logoutUser(w http.ResponseWriter, r *http.Request) string {
	username := ""
	if rt, err := r.Cookie("refreshToken"); err == nil && rt.Value != "" {
		if uname, valid := db.ValidateRefreshToken(a.DB, rt.Value); valid {
			username = uname
		}
		_ = db.RevokeRefreshToken(a.DB, rt.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "refreshToken",
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
	if username != "" {
		uris, err := db.GetBackchannelLogoutURIsForUser(a.DB, username)
		if err != nil {
			log.Printf("backchannel logout: get URIs: %v", err)
		}
		_ = db.DeleteOAuthRefreshTokensByUser(a.DB, username)
		a.fireBackchannelLogout(username, uris)
	}
	return username
}

// GET /logout — clears the upstream session and shows a confirmation page.
// post_logout_redirect_uri, if provided, must share an origin with a registered OAuth client redirect URI.
func (a *App) LogoutGET(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	if redirectURI != "" {
		target := uriOrigin(redirectURI)
		if target == "" {
			http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
			return
		}
		allowed, err := db.AllOAuthRedirectURIs(a.DB)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		ok := false
		for _, u := range allowed {
			if uriOrigin(u) == target {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
			return
		}
	}

	a.logoutUser(w, r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = logoutPageTmpl.Execute(w, struct{ RedirectURI string }{redirectURI})
}

// POST /api/auth/logout  (CSRF-protected)
func (a *App) Logout(w http.ResponseWriter, r *http.Request) {
	a.logoutUser(w, r)
	jsonOK(w, map[string]bool{"ok": true})
}

// DELETE /api/auth/account  (requireAuth)
func (a *App) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if body.Password == "" {
		jsonErr(w, http.StatusBadRequest, "Password required")
		return
	}
	username := usernameFromContext(r)
	user, _ := db.GetUser(a.DB, username)
	if user == nil {
		jsonErr(w, http.StatusNotFound, "User not found")
		return
	}
	if auth.HashPassword(body.Password, user.Salt) != user.Hash {
		jsonErr(w, http.StatusUnauthorized, "Incorrect password")
		return
	}

	if user.IsAdmin {
		count, _ := db.CountAdmins(a.DB)
		if count <= 1 {
			jsonErr(w, http.StatusBadRequest, "Cannot delete the only admin account")
			return
		}
	}

	if err := db.DeleteUser(a.DB, username); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to delete account")
		return
	}
	_ = db.DeleteRefreshTokensByUser(a.DB, username)
	_ = db.DeleteAllPasskeysByUser(a.DB, username)
	_ = db.DeleteOAuthRefreshTokensByUser(a.DB, username)
	_ = db.DeleteOAuthAuthCodesByUser(a.DB, username)
	_ = db.DeletePasswordResetTokensByUser(a.DB, username)
	_ = db.DeleteEmailVerificationsByUser(a.DB, username)

	http.SetCookie(w, &http.Cookie{
		Name:    "refreshToken",
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
	jsonOK(w, map[string]bool{"ok": true})
}

// POST /api/auth/change-password  (requireAuth)
func (a *App) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if len(body.NewPassword) < 12 {
		jsonErr(w, http.StatusBadRequest, "New password must be at least 12 characters")
		return
	}
	username := usernameFromContext(r)
	user, _ := db.GetUser(a.DB, username)
	if user == nil {
		jsonErr(w, http.StatusBadRequest, "Not configured")
		return
	}
	if auth.HashPassword(body.CurrentPassword, user.Salt) != user.Hash {
		jsonErr(w, http.StatusUnauthorized, "Current password incorrect")
		return
	}

	saltBytes := make([]byte, 32)
	if _, err := rand.Read(saltBytes); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Password change failed")
		return
	}
	newSalt := hex.EncodeToString(saltBytes)
	newHash := auth.HashPassword(body.NewPassword, newSalt)
	plain, hashes, err := auth.GenerateRecoveryCodes(newSalt, 8)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Password change failed")
		return
	}

	user.Hash = newHash
	user.Salt = newSalt
	user.RecoveryCodes = hashes
	if err := db.UpdateUser(a.DB, user); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Password change failed")
		return
	}
	if err := db.DeleteRefreshTokensByUser(a.DB, username); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Password change failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "refreshToken", Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0),
	})
	jsonOK(w, map[string]any{"ok": true, "recoveryCodes": plain})
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func (a *App) issueSession(w http.ResponseWriter, r *http.Request, username string) (accessToken, csrfToken string, err error) {
	accessToken, err = auth.SignToken(a.privateKey(), a.Cfg.JWTIssuer, username, "account-manager", time.Hour)
	if err != nil {
		return
	}
	rtBytes := make([]byte, 48)
	if _, err = rand.Read(rtBytes); err != nil {
		return
	}
	rt := hex.EncodeToString(rtBytes)
	expiresAt := time.Now().Add(30 * 24 * time.Hour).UnixMilli()
	if err = db.SaveRefreshToken(a.DB, rt, expiresAt, username); err != nil {
		return
	}
	if err = db.PruneExpiredRefreshTokens(a.DB); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "refreshToken",
		Value:    rt,
		HttpOnly: true,
		Secure:   a.Cfg.IsProd,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   30 * 24 * 60 * 60,
		Path:     "/",
	})
	csrfToken = middleware.GenerateCSRFToken(w, r, a.Cfg.CsrfSecret, a.Cfg.IsProd)
	return
}

// POST /api/auth/forgot-password  (public)
func (a *App) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	// Always return ok — never reveal whether the email is registered.
	defer jsonOK(w, map[string]bool{"ok": true})

	user, _ := db.GetUserByEmail(a.DB, body.Email)
	if user == nil || body.Email == "" {
		return
	}

	tokBytes := make([]byte, 32)
	if _, err := rand.Read(tokBytes); err != nil {
		return
	}
	token := hex.EncodeToString(tokBytes)
	expiresAt := time.Now().Add(time.Hour).UnixMilli()
	if err := db.SavePasswordResetToken(a.DB, token, user.Username, expiresAt); err != nil {
		return
	}

	// Build reset URL from request headers (same pattern as AdminCreateInvite).
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	resetURL := proto + "://" + host + "/accounts/?reset=" + token

	body2 := "Someone requested a password reset for your account.\n\n" +
		"Click the link below to set a new password (expires in 1 hour):\n\n" +
		resetURL + "\n\n" +
		"If you didn't request this, you can ignore this email.\n"

	mailer.Send(a.Cfg, user.Email, "Reset your password", body2) //nolint:errcheck
}

// POST /api/auth/reset-password  (public)
func (a *App) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
		TotpCode    string `json:"totpCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if len(body.NewPassword) < 12 {
		jsonErr(w, http.StatusBadRequest, "Password must be at least 12 characters")
		return
	}

	username, ok := db.GetPasswordResetToken(a.DB, body.Token)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "Invalid or expired reset link")
		return
	}

	user, _ := db.GetUser(a.DB, username)
	if user == nil {
		jsonErr(w, http.StatusInternalServerError, "User not found")
		return
	}

	if !auth.VerifyTOTP(user.TotpSecret, body.TotpCode) {
		jsonErr(w, http.StatusUnauthorized, "Invalid authenticator code")
		return
	}

	saltBytes := make([]byte, 32)
	if _, err := rand.Read(saltBytes); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Reset failed")
		return
	}
	newSalt := hex.EncodeToString(saltBytes)
	newHash := auth.HashPassword(body.NewPassword, newSalt)
	plain, hashes, err := auth.GenerateRecoveryCodes(newSalt, 8)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Reset failed")
		return
	}

	user.Hash = newHash
	user.Salt = newSalt
	user.RecoveryCodes = hashes
	if err := db.UpdateUser(a.DB, user); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Reset failed")
		return
	}
	db.DeleteRefreshTokensByUser(a.DB, username)         //nolint:errcheck
	db.DeletePasswordResetTokensByUser(a.DB, username)   //nolint:errcheck

	accessToken, csrfToken, err := a.issueSession(w, r, username)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Reset failed")
		return
	}
	jsonOK(w, map[string]any{
		"accessToken":   accessToken,
		"csrfToken":     csrfToken,
		"recoveryCodes": plain,
	})
}

// PUT /api/auth/email  (requireAuth)
func (a *App) UpdateEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	email := strings.TrimSpace(body.Email)
	if msg := validEmail(email); msg != "" {
		jsonErr(w, http.StatusBadRequest, msg)
		return
	}
	username := usernameFromContext(r)

	// Removing email: update directly, no verification needed.
	if email == "" {
		_ = db.DeleteEmailVerificationsByUser(a.DB, username)
		if err := db.UpdateUserEmail(a.DB, username, ""); err != nil {
			jsonErr(w, http.StatusInternalServerError, "Update failed")
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
		return
	}

	if err := a.sendEmailVerification(r, username, email); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to send verification email — check SMTP settings")
		return
	}
	jsonOK(w, map[string]any{"pending": true, "email": email})
}

// GET /api/auth/email/pending  (requireAuth)
func (a *App) PendingEmail(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	if email, ok := db.GetPendingEmailVerification(a.DB, username); ok {
		jsonOK(w, map[string]any{"email": email})
	} else {
		jsonOK(w, map[string]any{})
	}
}

// DELETE /api/auth/email/pending  (requireAuth, csrfProtect)
func (a *App) CancelPendingEmail(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	_ = db.DeleteEmailVerificationsByUser(a.DB, username)
	jsonOK(w, map[string]bool{"ok": true})
}

// GET /api/auth/email/verify  (public — token is the credential)
func (a *App) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		jsonErr(w, http.StatusBadRequest, "Missing token")
		return
	}
	username, email, ok := db.GetAndConsumeEmailVerificationToken(a.DB, token)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "Invalid or expired verification link")
		return
	}
	if err := db.UpdateUserEmail(a.DB, username, email); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to save email")
		return
	}
	jsonOK(w, map[string]any{"ok": true, "email": email})
}

func (a *App) sendEmailVerification(r *http.Request, username, email string) error {
	tokBytes := make([]byte, 32)
	if _, err := rand.Read(tokBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokBytes)
	expiresAt := time.Now().Add(24 * time.Hour).UnixMilli()
	if err := db.SaveEmailVerificationToken(a.DB, token, username, email, expiresAt); err != nil {
		return err
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "http"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	verifyURL := proto + "://" + host + "/accounts/?verify-email=" + token

	body := "Please verify your email address by clicking the link below (expires in 24 hours):\n\n" +
		verifyURL + "\n\n" +
		"If you didn't request this, you can ignore this email.\n"

	// If SMTP is not configured (dev/test), skip sending — the token is
	// already in the DB and the caller can retrieve it directly.
	if a.Cfg.SMTPHost == "" {
		return nil
	}
	return mailer.Send(a.Cfg, email, "Verify your email address", body)
}

func consumeRecoveryCode(user *db.User, code string) (int, bool) {
	if code == "" {
		return -1, false
	}
	candidate := auth.HashPassword(code, user.Salt)
	for i, h := range user.RecoveryCodes {
		if h == candidate {
			return i, true
		}
	}
	return -1, false
}
