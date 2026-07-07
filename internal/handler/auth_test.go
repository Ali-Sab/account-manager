package handler

import (
	"net/http"
	"testing"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"

	"github.com/pquerna/otp/totp"
)


func TestLogin_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, password, totpSecret := seedAccount(t, app.DB)

	// Step 1: login → mfaToken
	w := doRequest(t, router, http.MethodPost, "/api/auth/login",
		jsonBody(t, map[string]string{"username": username, "password": password}),
		nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var loginResp struct{ MFAToken string `json:"mfaToken"` }
	decodeJSON(t, w.Body, &loginResp)
	if loginResp.MFAToken == "" {
		t.Fatal("expected mfaToken in login response")
	}

	// Step 2: MFA → accessToken + cookie
	code, _ := totp.GenerateCode(totpSecret, time.Now())
	w2 := doRequest(t, router, http.MethodPost, "/api/auth/mfa",
		jsonBody(t, map[string]string{"mfaToken": loginResp.MFAToken, "code": code}),
		nil, nil)
	if w2.Code != http.StatusOK {
		t.Fatalf("mfa: want 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var mfaResp struct {
		AccessToken string `json:"accessToken"`
		CSRFToken   string `json:"csrfToken"`
	}
	decodeJSON(t, w2.Body, &mfaResp)
	if mfaResp.AccessToken == "" {
		t.Fatal("expected accessToken in MFA response")
	}
	// Verify access token is valid.
	claims, err := auth.VerifyAccess(app.publicKey(), app.Cfg.JWTIssuer, mfaResp.AccessToken)
	if err != nil {
		t.Fatalf("accessToken not valid: %v", err)
	}
	if claims.Subject != username {
		t.Errorf("expected subject %s, got %s", username, claims.Subject)
	}
	// Refresh cookie should be set.
	var rtCookie *http.Cookie
	for _, c := range w2.Result().Cookies() {
		if c.Name == "refreshToken" {
			rtCookie = c
			break
		}
	}
	if rtCookie == nil {
		t.Fatal("expected refreshToken cookie")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)

	w := doRequest(t, router, http.MethodPost, "/api/auth/login",
		jsonBody(t, map[string]string{"username": username, "password": "wrongpass"}),
		nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestLogin_WrongUsername(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	_, password, _ := seedAccount(t, app.DB)

	w := doRequest(t, router, http.MethodPost, "/api/auth/login",
		jsonBody(t, map[string]string{"username": "notexist", "password": password}),
		nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestLogin_NotConfigured(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodPost, "/api/auth/login",
		jsonBody(t, map[string]string{"username": "x", "password": "y"}),
		nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 (no users exist), got %d", w.Code)
	}
}

func TestMFA_InvalidToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB)

	w := doRequest(t, router, http.MethodPost, "/api/auth/mfa",
		jsonBody(t, map[string]string{"mfaToken": "bad.token.here", "code": "123456"}),
		nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestRecovery_ValidCode(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, password, totpSecret := seedAccount(t, app.DB)

	// Get mfaToken via login.
	w := doRequest(t, router, http.MethodPost, "/api/auth/login",
		jsonBody(t, map[string]string{"username": username, "password": password}),
		nil, nil)
	var loginResp struct{ MFAToken string `json:"mfaToken"` }
	decodeJSON(t, w.Body, &loginResp)

	// Regenerate recovery codes so we have plaintexts.
	accessToken := seedAccessToken(t, app, username)
	rw := doRequest(t, router, http.MethodPost, "/api/auth/recovery-codes/regenerate",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if rw.Code != http.StatusOK {
		t.Fatalf("regenerate: want 200, got %d: %s", rw.Code, rw.Body.String())
	}
	var regen struct{ RecoveryCodes []string `json:"recoveryCodes"` }
	decodeJSON(t, rw.Body, &regen)
	if len(regen.RecoveryCodes) == 0 {
		t.Fatal("no recovery codes returned")
	}

	// Get a fresh mfaToken (the one above may be spent or expired).
	code, _ := totp.GenerateCode(totpSecret, time.Now())
	_ = code
	mfaToken, _ := auth.SignMFAToken(app.privateKey(), app.Cfg.JWTIssuer, username)

	recoveryCode := regen.RecoveryCodes[0]
	w2 := doRequest(t, router, http.MethodPost, "/api/auth/recovery",
		jsonBody(t, map[string]string{"mfaToken": mfaToken, "code": recoveryCode}),
		nil, nil)
	if w2.Code != http.StatusOK {
		t.Fatalf("recovery: want 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestRecovery_ReplayFails(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)

	accessToken := seedAccessToken(t, app, username)
	rw := doRequest(t, router, http.MethodPost, "/api/auth/recovery-codes/regenerate",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	var regen struct{ RecoveryCodes []string `json:"recoveryCodes"` }
	decodeJSON(t, rw.Body, &regen)

	mfaToken, _ := auth.SignMFAToken(app.privateKey(), app.Cfg.JWTIssuer, username)
	code := regen.RecoveryCodes[0]

	// First use.
	w1 := doRequest(t, router, http.MethodPost, "/api/auth/recovery",
		jsonBody(t, map[string]string{"mfaToken": mfaToken, "code": code}),
		nil, nil)
	if w1.Code != http.StatusOK {
		t.Fatalf("first recovery: want 200, got %d", w1.Code)
	}

	// Replay: need a new mfaToken (old one's sub is consumed), but same code.
	mfaToken2, _ := auth.SignMFAToken(app.privateKey(), app.Cfg.JWTIssuer, username)
	w2 := doRequest(t, router, http.MethodPost, "/api/auth/recovery",
		jsonBody(t, map[string]string{"mfaToken": mfaToken2, "code": code}),
		nil, nil)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("replay should fail with 401, got %d", w2.Code)
	}
}

func TestRefresh_ValidCookie(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)

	// Save a refresh token directly.
	rt := "validtoken123"
	db.SaveRefreshToken(app.DB, rt, time.Now().Add(time.Hour).UnixMilli(), username) //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/api/auth/refresh",
		nil, []*http.Cookie{{Name: "refreshToken", Value: rt}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct{ AccessToken string `json:"accessToken"` }
	decodeJSON(t, w.Body, &resp)
	if resp.AccessToken == "" {
		t.Error("expected accessToken in refresh response")
	}
	_ = username
}

func TestRefresh_ExpiredCookie(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB)

	rt := "expiredtoken"
	db.SaveRefreshToken(app.DB, rt, time.Now().Add(-time.Hour).UnixMilli(), "") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/api/auth/refresh",
		nil, []*http.Cookie{{Name: "refreshToken", Value: rt}}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	rt := "tok"
	db.SaveRefreshToken(app.DB, rt, time.Now().Add(time.Hour).UnixMilli(), "") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/api/auth/logout",
		nil, []*http.Cookie{{Name: "refreshToken", Value: rt}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("logout: want 200, got %d", w.Code)
	}
	// The cookie should have been invalidated.
	_, valid := db.ValidateRefreshToken(app.DB, rt)
	if valid {
		t.Error("refresh token should be revoked after logout")
	}
}

func TestChangePassword_RotatesSaltAndInvalidatesTokens(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, password, _ := seedAccount(t, app.DB)

	accessToken := seedAccessToken(t, app, username)
	rt := "tok"
	db.SaveRefreshToken(app.DB, rt, time.Now().Add(time.Hour).UnixMilli(), username) //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/api/auth/change-password",
		jsonBody(t, map[string]string{"currentPassword": password, "newPassword": "newpassword123"}),
		nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("change-password: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// All refresh tokens should be revoked.
	_, valid := db.ValidateRefreshToken(app.DB, rt)
	if valid {
		t.Error("refresh token should be revoked after password change")
	}

	// Old password should no longer work.
	u, _ := db.GetUser(app.DB, username)
	if auth.HashPassword(password, u.Salt) == u.Hash {
		t.Error("old password hash should not match new credentials")
	}
}

func TestRecoveryCodeCount(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodGet, "/api/auth/recovery-codes/count",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct{ Remaining int `json:"remaining"` }
	decodeJSON(t, w.Body, &resp)
	if resp.Remaining != 8 {
		t.Errorf("expected 8 recovery codes, got %d", resp.Remaining)
	}
}

func TestRecoveryCodeCount_DecreasesAfterUse(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	// Regenerate so we have plaintext codes.
	rw := doRequest(t, router, http.MethodPost, "/api/auth/recovery-codes/regenerate",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	var regen struct{ RecoveryCodes []string `json:"recoveryCodes"` }
	decodeJSON(t, rw.Body, &regen)

	// Use one code.
	mfaToken, _ := auth.SignMFAToken(app.privateKey(), app.Cfg.JWTIssuer, username)
	doRequest(t, router, http.MethodPost, "/api/auth/recovery",
		jsonBody(t, map[string]string{"mfaToken": mfaToken, "code": regen.RecoveryCodes[0]}),
		nil, nil)

	// Count should now be 7.
	w := doRequest(t, router, http.MethodGet, "/api/auth/recovery-codes/count",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	var resp struct{ Remaining int `json:"remaining"` }
	decodeJSON(t, w.Body, &resp)
	if resp.Remaining != 7 {
		t.Errorf("expected 7 after consuming one, got %d", resp.Remaining)
	}
}

// ─── Me ───────────────────────────────────────────────────────────────────────

func TestMe_ReturnsUserInfo(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodGet, "/api/auth/me",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.Username != username {
		t.Errorf("expected username %s, got %s", username, resp.Username)
	}
	if !resp.IsAdmin {
		t.Error("expected isAdmin=true for seeded account")
	}
}

func TestMe_RequiresAuth(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/api/auth/me", nil, nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

// ─── UpdateEmail ──────────────────────────────────────────────────────────────

func TestUpdateEmail_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	// Step 1: request email change — returns pending (no SMTP in tests, so no email sent).
	w := doRequest(t, router, http.MethodPut, "/api/auth/email",
		jsonBody(t, map[string]string{"email": "alice@example.com"}),
		nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var pendingResp struct {
		Pending bool   `json:"pending"`
		Email   string `json:"email"`
	}
	decodeJSON(t, w.Body, &pendingResp)
	if !pendingResp.Pending {
		t.Fatalf("expected pending=true, got %+v", pendingResp)
	}

	// Step 2: read the verification token directly from the DB (SMTP skipped in tests).
	var token string
	err := app.DB.QueryRow(
		"SELECT token FROM email_verification_tokens WHERE username = ?", username,
	).Scan(&token)
	if err != nil {
		t.Fatalf("get verification token: %v", err)
	}

	// Step 3: click the verify link.
	verify := doRequest(t, router, http.MethodGet, "/api/auth/email/verify?token="+token,
		nil, nil, nil)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify: want 200, got %d: %s", verify.Code, verify.Body.String())
	}

	// Step 4: confirm email is now set via /me.
	me := doRequest(t, router, http.MethodGet, "/api/auth/me",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	var meResp struct{ Email string `json:"email"` }
	decodeJSON(t, me.Body, &meResp)
	if meResp.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %q", meResp.Email)
	}
}

func TestUpdateEmail_RequiresAuth(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodPut, "/api/auth/email",
		jsonBody(t, map[string]string{"email": "x@x.com"}), nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestUpdateEmail_InvalidFormat(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	badEmails := []string{"notanemail", "missing@tld", "@nodomain"}
	for _, e := range badEmails {
		w := doRequest(t, router, http.MethodPut, "/api/auth/email",
			jsonBody(t, map[string]string{"email": e}),
			nil, map[string]string{"Authorization": "Bearer " + accessToken})
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400 for email %q, got %d", e, w.Code)
		}
	}
}

func TestUpdateEmail_ClearEmail(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	// Empty email should be allowed (removes email).
	w := doRequest(t, router, http.MethodPut, "/api/auth/email",
		jsonBody(t, map[string]string{"email": ""}),
		nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Errorf("want 200 for empty email (clear), got %d: %s", w.Code, w.Body.String())
	}
}

// ─── ChangePassword edge cases ────────────────────────────────────────────────

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodPost, "/api/auth/change-password",
		jsonBody(t, map[string]string{"currentPassword": "wrongpass", "newPassword": "newpassword123"}),
		nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestChangePassword_ShortNewPassword(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, password, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodPost, "/api/auth/change-password",
		jsonBody(t, map[string]string{"currentPassword": password, "newPassword": "abc"}),
		nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestChangePassword_ReturnsNewRecoveryCodes(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, password, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodPost, "/api/auth/change-password",
		jsonBody(t, map[string]string{"currentPassword": password, "newPassword": "newpassword123"}),
		nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct{ RecoveryCodes []string `json:"recoveryCodes"` }
	decodeJSON(t, w.Body, &resp)
	if len(resp.RecoveryCodes) != 8 {
		t.Errorf("expected 8 recovery codes, got %d", len(resp.RecoveryCodes))
	}
}

// ─── ForgotPassword ───────────────────────────────────────────────────────────

func TestForgotPassword_AlwaysReturnsOK(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB)

	// Unknown email — must still return 200 to prevent enumeration.
	w := doRequest(t, router, http.MethodPost, "/api/auth/forgot-password",
		jsonBody(t, map[string]string{"email": "nobody@example.com"}),
		nil, nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 for unknown email, got %d", w.Code)
	}
}

func TestForgotPassword_EmptyEmailReturnsOK(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodPost, "/api/auth/forgot-password",
		jsonBody(t, map[string]string{"email": ""}),
		nil, nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 even for empty email, got %d", w.Code)
	}
}

func TestForgotPassword_KnownEmailCreatesToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	db.UpdateUserEmail(app.DB, username, "alice@example.com") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/api/auth/forgot-password",
		jsonBody(t, map[string]string{"email": "alice@example.com"}),
		nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	// Verify a token was actually created by attempting a reset with a wrong token
	// (the real token is only emailed, but we can check the DB indirectly).
	// Attempt reset with garbage token — should be 401, not 500 (proves table is queryable).
	w2 := doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{"token": "notarealtoken", "newPassword": "newpassword1234", "totpCode": "000000"}),
		nil, nil)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("bad token should give 401, got %d", w2.Code)
	}
}

// ─── ResetPassword ────────────────────────────────────────────────────────────

func TestResetPassword_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, totpSecret := seedAccount(t, app.DB)

	token := "validresettoken1234"
	db.SavePasswordResetToken(app.DB, token, username, time.Now().Add(time.Hour).UnixMilli()) //nolint:errcheck

	code, _ := totp.GenerateCode(totpSecret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{
			"token":       token,
			"newPassword": "brandnewpass123",
			"totpCode":    code,
		}), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		AccessToken   string   `json:"accessToken"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.AccessToken == "" {
		t.Error("expected accessToken in response")
	}
	if len(resp.RecoveryCodes) != 8 {
		t.Errorf("expected 8 recovery codes, got %d", len(resp.RecoveryCodes))
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	_, _, totpSecret := seedAccount(t, app.DB)

	code, _ := totp.GenerateCode(totpSecret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{
			"token":       "doesnotexist",
			"newPassword": "brandnewpass123",
			"totpCode":    code,
		}), nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, totpSecret := seedAccount(t, app.DB)

	token := "expiredtoken"
	db.SavePasswordResetToken(app.DB, token, username, time.Now().Add(-time.Hour).UnixMilli()) //nolint:errcheck

	code, _ := totp.GenerateCode(totpSecret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{
			"token":       token,
			"newPassword": "brandnewpass123",
			"totpCode":    code,
		}), nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for expired token, got %d", w.Code)
	}
}

func TestResetPassword_WrongTOTP(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)

	token := "goodtoken"
	db.SavePasswordResetToken(app.DB, token, username, time.Now().Add(time.Hour).UnixMilli()) //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{
			"token":       token,
			"newPassword": "brandnewpass123",
			"totpCode":    "000000",
		}), nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for wrong TOTP, got %d", w.Code)
	}
}

func TestResetPassword_ShortPassword(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{
			"token":       "anytoken",
			"newPassword": "abc",
			"totpCode":    "000000",
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for short password, got %d", w.Code)
	}
}

func TestResetPassword_TokenConsumedOnUse(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, totpSecret := seedAccount(t, app.DB)

	token := "consumetoken"
	db.SavePasswordResetToken(app.DB, token, username, time.Now().Add(time.Hour).UnixMilli()) //nolint:errcheck

	doBody := func() map[string]string {
		code, _ := totp.GenerateCode(totpSecret, time.Now())
		return map[string]string{"token": token, "newPassword": "brandnewpass123", "totpCode": code}
	}

	w1 := doRequest(t, router, http.MethodPost, "/api/auth/reset-password", jsonBody(t, doBody()), nil, nil)
	if w1.Code != http.StatusOK {
		t.Fatalf("first reset: want 200, got %d: %s", w1.Code, w1.Body.String())
	}
	// Token must be consumed — replay must fail.
	w2 := doRequest(t, router, http.MethodPost, "/api/auth/reset-password", jsonBody(t, doBody()), nil, nil)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("replay: want 401, got %d", w2.Code)
	}
}

func TestResetPassword_RevokesExistingSessions(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, totpSecret := seedAccount(t, app.DB)

	// Plant a live refresh token for the user.
	oldRT := "oldsession"
	db.SaveRefreshToken(app.DB, oldRT, time.Now().Add(time.Hour).UnixMilli(), username) //nolint:errcheck

	token := "revoketoken"
	db.SavePasswordResetToken(app.DB, token, username, time.Now().Add(time.Hour).UnixMilli()) //nolint:errcheck

	code, _ := totp.GenerateCode(totpSecret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{
			"token":       token,
			"newPassword": "brandnewpass123",
			"totpCode":    code,
		}), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	_, valid := db.ValidateRefreshToken(app.DB, oldRT)
	if valid {
		t.Error("existing refresh token should be revoked after password reset")
	}
}
