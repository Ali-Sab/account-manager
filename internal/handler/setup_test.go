package handler

import (
	"net/http"
	"testing"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"

	"github.com/pquerna/otp/totp"
)

func TestSetupStatus_Unconfigured(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/api/setup/status", nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Configured  bool `json:"configured"`
		HasPasskeys bool `json:"hasPasskeys"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.Configured {
		t.Error("expected configured=false on fresh DB")
	}
}

func TestSetupStatus_Configured(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB)

	w := doRequest(t, router, http.MethodGet, "/api/setup/status", nil, nil, nil)
	var resp struct{ Configured bool `json:"configured"` }
	decodeJSON(t, w.Body, &resp)
	if !resp.Configured {
		t.Error("expected configured=true after seedAccount")
	}
}

func TestSetupSecret_ReturnsQR(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/api/setup/secret", nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Secret    string `json:"secret"`
		Formatted string `json:"formatted"`
		QRDataURL string `json:"qrDataUrl"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.Secret == "" {
		t.Error("expected non-empty secret")
	}
	if resp.QRDataURL == "" {
		t.Error("expected QR data URL")
	}
}

func TestSetupSecret_ForbiddenWhenConfigured(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB)

	w := doRequest(t, router, http.MethodGet, "/api/setup/secret", nil, nil, nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
}

func TestSetup_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	// Get secret first.
	w := doRequest(t, router, http.MethodGet, "/api/setup/secret", nil, nil, nil)
	var secretResp struct{ Secret string `json:"secret"` }
	decodeJSON(t, w.Body, &secretResp)

	code, _ := totp.GenerateCode(secretResp.Secret, time.Now())
	w2 := doRequest(t, router, http.MethodPost, "/api/setup",
		jsonBody(t, map[string]string{
			"username": "alice",
			"password": "password1234",
			"totpCode": code,
		}), nil, nil)
	if w2.Code != http.StatusOK {
		t.Fatalf("setup: want 200, got %d: %s", w2.Code, w2.Body.String())
	}

	// User should now exist.
	u, _ := db.GetUser(app.DB, "alice")
	if u == nil {
		t.Fatal("expected user alice to be created after setup")
	}
	if !u.IsAdmin {
		t.Error("first user should be admin")
	}
}

func TestSetup_InvalidTOTP(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	doRequest(t, router, http.MethodGet, "/api/setup/secret", nil, nil, nil) //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/api/setup",
		jsonBody(t, map[string]string{
			"username": "alice",
			"password": "password1234",
			"totpCode": "000000",
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestSetup_ForbiddenWhenAlreadyConfigured(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	_, _, totpSecret := seedAccount(t, app.DB)

	code, _ := totp.GenerateCode(totpSecret, time.Now())
	w := doRequest(t, router, http.MethodPost, "/api/setup",
		jsonBody(t, map[string]string{
			"username": "alice",
			"password": "password1234",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
}

func TestSetup_ShortPassword(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	secret, _ := auth.GenerateSecret()
	db.WritePendingSetup(app.DB, &db.PendingSetup{Secret: secret, CreatedAt: time.Now().UnixMilli()}) //nolint:errcheck
	code, _ := totp.GenerateCode(secret, time.Now())

	w := doRequest(t, router, http.MethodPost, "/api/setup",
		jsonBody(t, map[string]string{
			"username": "alice",
			"password": "abc",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for short password, got %d", w.Code)
	}
}

func TestSetup_InvalidUsername(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	secret, _ := auth.GenerateSecret()
	db.WritePendingSetup(app.DB, &db.PendingSetup{Secret: secret, CreatedAt: time.Now().UnixMilli()}) //nolint:errcheck
	code, _ := totp.GenerateCode(secret, time.Now())

	cases := []string{"", "alice bob", "alice@bob", "a very long username that exceeds the limit"}
	for _, u := range cases {
		w := doRequest(t, router, http.MethodPost, "/api/setup",
			jsonBody(t, map[string]string{
				"username": u,
				"password": "password1234",
				"totpCode": code,
			}), nil, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400 for invalid username %q, got %d", u, w.Code)
		}
	}
}

func TestSetup_InvalidEmail(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	secret, _ := auth.GenerateSecret()
	db.WritePendingSetup(app.DB, &db.PendingSetup{Secret: secret, CreatedAt: time.Now().UnixMilli()}) //nolint:errcheck
	code, _ := totp.GenerateCode(secret, time.Now())

	w := doRequest(t, router, http.MethodPost, "/api/setup",
		jsonBody(t, map[string]string{
			"username": "alice",
			"email":    "notanemail",
			"password": "password1234",
			"totpCode": code,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid email, got %d", w.Code)
	}
}
