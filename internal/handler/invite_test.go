package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"

	"github.com/pquerna/otp/totp"
)

// seedInvite plants an invite row directly in the DB and returns the token.
func seedInvite(t *testing.T, app *App) string {
	t.Helper()
	token := "testinvitetoken"
	if err := db.CreatePendingInvite(app.DB, token, "alice"); err != nil {
		t.Fatalf("CreatePendingInvite: %v", err)
	}
	return token
}

// seedInviteWithSecret plants an invite that already has a TOTP secret assigned,
// as if InviteSecret had already been called. Returns (token, totpSecret).
func seedInviteWithSecret(t *testing.T, app *App) (token, totpSecret string) {
	t.Helper()
	token = seedInvite(t, app)
	secret, err := auth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if err := db.SetPendingInviteSecret(app.DB, token, secret); err != nil {
		t.Fatalf("SetPendingInviteSecret: %v", err)
	}
	return token, secret
}

// ─── InviteSecret ─────────────────────────────────────────────────────────────

func TestInviteSecret_ValidToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token := seedInvite(t, app)

	w := doRequest(t, router, http.MethodGet, "/api/invite/secret?token="+token, nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Secret    string `json:"secret"`
		QRDataURL string `json:"qrDataUrl"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.Secret == "" {
		t.Error("expected non-empty TOTP secret")
	}
	if resp.QRDataURL == "" {
		t.Error("expected non-empty QR data URL")
	}
}

func TestInviteSecret_MissingToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/api/invite/secret", nil, nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing token, got %d", w.Code)
	}
}

func TestInviteSecret_InvalidToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/api/invite/secret?token=doesnotexist", nil, nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid token, got %d", w.Code)
	}
}

func TestInviteSecret_ExpiredToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	// Plant an invite with a creation time >48h ago.
	if err := db.CreatePendingInvite(app.DB, "expiredinvite", "alice"); err != nil {
		t.Fatalf("CreatePendingInvite: %v", err)
	}
	// Directly overwrite the created_at to make it expired.
	// We do this by reading back and checking — the invite was just created so
	// we update via a raw DB exec using the app.DB directly.
	if _, err := app.DB.Exec(
		"UPDATE pending_invites SET created_at = ? WHERE token = ?",
		time.Now().Add(-49*time.Hour).UnixMilli(), "expiredinvite",
	); err != nil {
		t.Fatalf("backdating invite: %v", err)
	}

	w := doRequest(t, router, http.MethodGet, "/api/invite/secret?token=expiredinvite", nil, nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for expired invite, got %d", w.Code)
	}
}

// ─── AcceptInvite ─────────────────────────────────────────────────────────────

func TestAcceptInvite_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token, secret := seedInviteWithSecret(t, app)

	code, _ := totp.GenerateCode(secret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    token,
			"username": "bob",
			"email":    "bob@example.com",
			"password": "password1234",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		OK            bool     `json:"ok"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	decodeJSON(t, w.Body, &resp)
	if !resp.OK {
		t.Error("expected ok=true")
	}
	if len(resp.RecoveryCodes) != 8 {
		t.Errorf("expected 8 recovery codes, got %d", len(resp.RecoveryCodes))
	}
	// User should exist in DB.
	u, _ := db.GetUser(app.DB, "bob")
	if u == nil {
		t.Fatal("expected bob to be created in DB")
	}
	if u.IsAdmin {
		t.Error("invited user should not be admin")
	}
}

func TestAcceptInvite_InvalidToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    "doesnotexist",
			"username": "bob",
			"password": "password1234",
			"totpCode": "000000",
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid token, got %d", w.Code)
	}
}

func TestAcceptInvite_NoTOTPSecret(t *testing.T) {
	// Invite exists but InviteSecret has not been called yet — no secret assigned.
	app := newTestApp(t)
	router := buildRouter(app)
	token := seedInvite(t, app)

	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    token,
			"username": "bob",
			"password": "password1234",
			"totpCode": "000000",
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 when invite has no TOTP secret, got %d", w.Code)
	}
}

func TestAcceptInvite_ExpiredToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token, secret := seedInviteWithSecret(t, app)

	if _, err := app.DB.Exec(
		"UPDATE pending_invites SET created_at = ? WHERE token = ?",
		time.Now().Add(-49*time.Hour).UnixMilli(), token,
	); err != nil {
		t.Fatalf("backdating invite: %v", err)
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    token,
			"username": "bob",
			"password": "password1234",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for expired invite, got %d", w.Code)
	}
}

func TestAcceptInvite_WrongTOTP(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token, _ := seedInviteWithSecret(t, app)

	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    token,
			"username": "bob",
			"password": "password1234",
			"totpCode": "000000",
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for wrong TOTP, got %d", w.Code)
	}
}

func TestAcceptInvite_ShortPassword(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token, secret := seedInviteWithSecret(t, app)

	code, _ := totp.GenerateCode(secret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    token,
			"username": "bob",
			"password": "abc",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for short password, got %d", w.Code)
	}
}

func TestAcceptInvite_DuplicateUsername(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB) // creates "alice"
	token, secret := seedInviteWithSecret(t, app)

	code, _ := totp.GenerateCode(secret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    token,
			"username": "alice", // already taken
			"password": "password1234",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for duplicate username, got %d", w.Code)
	}
}

func TestAcceptInvite_MissingRequiredFields(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{"token": "x"}), // missing username, password, totpCode
		nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing fields, got %d", w.Code)
	}
}

func TestAcceptInvite_InvalidUsername(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token, secret := seedInviteWithSecret(t, app)

	cases := []string{"", "bob smith", "bob@example", "averylongusernamethatexceedsthemaximumlengthallowed"}
	for _, u := range cases {
		code, _ := totp.GenerateCode(secret, time.Now())
		w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
			jsonBody(t, map[string]string{
				"token":    token,
				"username": u,
				"password": "password1234",
				"totpCode": code,
			}), nil, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400 for invalid username %q, got %d", u, w.Code)
		}
	}
}

func TestAcceptInvite_InvalidEmail(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token, secret := seedInviteWithSecret(t, app)

	code, _ := totp.GenerateCode(secret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/invite/accept",
		jsonBody(t, map[string]string{
			"token":    token,
			"username": "bob",
			"email":    "notanemail",
			"password": "password1234",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid email, got %d", w.Code)
	}
}

func TestAcceptInvite_SingleUse(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	token, secret := seedInviteWithSecret(t, app)

	doAccept := func(username string) *httptest.ResponseRecorder {
		code, _ := totp.GenerateCode(secret, time.Now())
		return doRequest(t, router, http.MethodPost, "/api/invite/accept",
			jsonBody(t, map[string]string{
				"token":    token,
				"username": username,
				"password": "password1234",
				"totpCode": code,
			}), nil, nil)
	}

	w1 := doAccept("bob")
	if w1.Code != http.StatusOK {
		t.Fatalf("first accept: want 200, got %d: %s", w1.Code, w1.Body.String())
	}
	// Second use of same invite token — invite was deleted after first use.
	w2 := doAccept("carol")
	if w2.Code != http.StatusBadRequest {
		t.Errorf("replay: want 400, got %d", w2.Code)
	}
}
