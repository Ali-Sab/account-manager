package handler

import (
	"net/http"
	"testing"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"
)

// seedNonAdminUser creates a second user with IsAdmin=false and returns their access token.
func seedNonAdminUser(t *testing.T, app *App, username string) string {
	t.Helper()
	salt := "aabbccddeeff00112233445566778899"
	hash := auth.HashPassword("pass123", salt)
	secret, err := auth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	_, hashes, err := auth.GenerateRecoveryCodes(salt, 8)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if err := db.CreateUser(app.DB, &db.User{
		Username:      username,
		Hash:          hash,
		Salt:          salt,
		TotpSecret:    secret,
		RecoveryCodes: hashes,
		IsAdmin:       false,
		CreatedAt:     time.Now().UnixMilli(),
	}); err != nil {
		t.Fatalf("CreateUser(%s): %v", username, err)
	}
	return seedAccessToken(t, app, username)
}

// ─── AdminOnly middleware ─────────────────────────────────────────────────────

func TestAdminOnly_NonAdminForbidden(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB) // alice (admin)
	bobToken := seedNonAdminUser(t, app, "bob")

	w := doRequest(t, router, http.MethodGet, "/api/admin/users",
		nil, nil, map[string]string{"Authorization": "Bearer " + bobToken})
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403 for non-admin, got %d", w.Code)
	}
}

func TestAdminOnly_UnauthenticatedRejected(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/api/admin/users", nil, nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without token, got %d", w.Code)
	}
}

// ─── AdminListUsers ───────────────────────────────────────────────────────────

func TestAdminListUsers_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)
	seedNonAdminUser(t, app, "bob")

	w := doRequest(t, router, http.MethodGet, "/api/admin/users",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp []struct {
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}
	decodeJSON(t, w.Body, &resp)
	if len(resp) != 2 {
		t.Fatalf("expected 2 users, got %d", len(resp))
	}
	found := map[string]bool{}
	for _, u := range resp {
		found[u.Username] = true
	}
	if !found["alice"] || !found["bob"] {
		t.Errorf("expected alice and bob in list, got %v", resp)
	}
}

func TestAdminListUsers_NonAdmin(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB)
	bobToken := seedNonAdminUser(t, app, "bob")

	w := doRequest(t, router, http.MethodGet, "/api/admin/users",
		nil, nil, map[string]string{"Authorization": "Bearer " + bobToken})
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
}

// ─── AdminDeleteUser ──────────────────────────────────────────────────────────

func TestAdminDeleteUser_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)
	seedNonAdminUser(t, app, "bob")

	w := doRequest(t, router, http.MethodDelete, "/api/admin/users/bob",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	// Bob should be gone.
	u, _ := db.GetUser(app.DB, "bob")
	if u != nil {
		t.Error("expected bob to be deleted from DB")
	}
}

func TestAdminDeleteUser_SelfDeleteForbidden(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodDelete, "/api/admin/users/alice",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for self-delete, got %d", w.Code)
	}
}

func TestAdminDeleteUser_RevokesRefreshTokens(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)
	seedNonAdminUser(t, app, "bob")

	// Plant a refresh token for bob.
	bobRT := "bobrefreshtoken"
	db.SaveRefreshToken(app.DB, bobRT, time.Now().Add(time.Hour).UnixMilli(), "bob") //nolint:errcheck

	doRequest(t, router, http.MethodDelete, "/api/admin/users/bob",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})

	_, valid := db.ValidateRefreshToken(app.DB, bobRT)
	if valid {
		t.Error("bob's refresh token should be revoked after deletion")
	}
}

func TestAdminDeleteUser_NonAdmin(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB) // alice (admin, target)
	bobToken := seedNonAdminUser(t, app, "bob")

	w := doRequest(t, router, http.MethodDelete, "/api/admin/users/alice",
		nil, nil, map[string]string{"Authorization": "Bearer " + bobToken})
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403 for non-admin delete, got %d", w.Code)
	}
}

// ─── AdminCreateInvite ────────────────────────────────────────────────────────

func TestAdminCreateInvite_HappyPath(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodPost, "/api/admin/invite",
		nil, nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.Token == "" {
		t.Error("expected non-empty invite token")
	}
	if resp.URL == "" {
		t.Error("expected non-empty invite URL")
	}
	// Verify token is stored in DB.
	invite, err := db.GetPendingInvite(app.DB, resp.Token)
	if err != nil || invite == nil {
		t.Errorf("invite token not found in DB: %v", err)
	}
	if invite.InvitedBy != username {
		t.Errorf("expected invitedBy=%s, got %s", username, invite.InvitedBy)
	}
}

func TestAdminCreateInvite_NonAdmin(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccount(t, app.DB)
	bobToken := seedNonAdminUser(t, app, "bob")

	w := doRequest(t, router, http.MethodPost, "/api/admin/invite",
		nil, nil, map[string]string{"Authorization": "Bearer " + bobToken})
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403 for non-admin, got %d", w.Code)
	}
}
