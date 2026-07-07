package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"

	qrcode "github.com/skip2/go-qrcode"
)

// GET /api/setup/status
func (a *App) SetupStatus(w http.ResponseWriter, r *http.Request) {
	count, _ := db.CountUsers(a.DB)
	passkeys, _ := db.ReadAllPasskeyCredentials(a.DB)
	jsonOK(w, map[string]any{
		"configured":  count > 0,
		"hasPasskeys": len(passkeys) > 0,
	})
}

// GET /api/setup/secret
func (a *App) SetupSecret(w http.ResponseWriter, r *http.Request) {
	count, _ := db.CountUsers(a.DB)
	if count > 0 {
		jsonErr(w, http.StatusForbidden, "Already configured")
		return
	}
	secret, err := auth.GenerateSecret()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to generate secret")
		return
	}
	if err := db.WritePendingSetup(a.DB, &db.PendingSetup{Secret: secret, CreatedAt: time.Now().UnixMilli()}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to save setup state")
		return
	}
	jsonOK(w, totpSecretResponse(secret, "setup"))
}

// POST /api/setup
func (a *App) Setup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTPCode string `json:"totpCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if body.Password == "" || body.TOTPCode == "" {
		jsonErr(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if msg := validUsername(body.Username); msg != "" {
		jsonErr(w, http.StatusBadRequest, msg)
		return
	}
	if msg := validEmail(body.Email); msg != "" {
		jsonErr(w, http.StatusBadRequest, msg)
		return
	}
	if len(body.Password) < 12 {
		jsonErr(w, http.StatusBadRequest, "Password must be at least 12 characters")
		return
	}

	count, _ := db.CountUsers(a.DB)
	if count > 0 {
		jsonErr(w, http.StatusForbidden, "Already configured")
		return
	}

	pending, _ := db.ReadPendingSetup(a.DB)
	if pending == nil || time.Now().UnixMilli()-pending.CreatedAt > 10*60*1000 {
		jsonErr(w, http.StatusBadRequest, "Setup session expired, refresh the page")
		return
	}
	if !auth.VerifyTOTP(pending.Secret, body.TOTPCode) {
		jsonErr(w, http.StatusBadRequest, "Invalid TOTP code")
		return
	}

	saltBytes := make([]byte, 32)
	if _, err := cryptoRandRead(saltBytes); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Setup failed")
		return
	}
	salt := encodeHex(saltBytes)
	hash := auth.HashPassword(body.Password, salt)
	plain, hashes, err := auth.GenerateRecoveryCodes(salt, 8)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Setup failed")
		return
	}

	username := strings.TrimSpace(body.Username)
	if err := db.CreateUser(a.DB, &db.User{
		Username:      username,
		Hash:          hash,
		Salt:          salt,
		TotpSecret:    pending.Secret,
		RecoveryCodes: hashes,
		IsAdmin:       true,
		CreatedAt:     time.Now().UnixMilli(),
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Setup failed")
		return
	}
	_ = db.WritePendingSetup(a.DB, nil)

	emailPending := false
	if email := strings.TrimSpace(body.Email); email != "" {
		if err := a.sendEmailVerification(r, username, email); err == nil {
			emailPending = true
		}
	}
	jsonOK(w, map[string]any{"ok": true, "recoveryCodes": plain, "emailPending": emailPending})
}

// GET /api/invite/secret?token=TOKEN
func (a *App) InviteSecret(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		jsonErr(w, http.StatusBadRequest, "Missing token")
		return
	}
	invite, _ := db.GetPendingInvite(a.DB, token)
	if invite == nil || time.Now().UnixMilli()-invite.CreatedAt > 48*60*60*1000 {
		jsonErr(w, http.StatusBadRequest, "Invalid or expired invite")
		return
	}
	secret, err := auth.GenerateSecret()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to generate secret")
		return
	}
	if err := db.SetPendingInviteSecret(a.DB, token, secret); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to save state")
		return
	}
	jsonOK(w, totpSecretResponse(secret, "invite"))
}

// POST /api/invite/accept
func (a *App) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTPCode string `json:"totpCode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid request")
		return
	}
	if body.Token == "" || body.Password == "" || body.TOTPCode == "" {
		jsonErr(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if msg := validUsername(body.Username); msg != "" {
		jsonErr(w, http.StatusBadRequest, msg)
		return
	}
	if msg := validEmail(body.Email); msg != "" {
		jsonErr(w, http.StatusBadRequest, msg)
		return
	}
	if len(body.Password) < 12 {
		jsonErr(w, http.StatusBadRequest, "Password must be at least 12 characters")
		return
	}

	invite, _ := db.GetPendingInvite(a.DB, body.Token)
	if invite == nil || invite.TotpSecret == "" || time.Now().UnixMilli()-invite.CreatedAt > 48*60*60*1000 {
		jsonErr(w, http.StatusBadRequest, "Invalid or expired invite")
		return
	}
	if !auth.VerifyTOTP(invite.TotpSecret, body.TOTPCode) {
		jsonErr(w, http.StatusBadRequest, "Invalid TOTP code")
		return
	}

	username := strings.TrimSpace(body.Username)
	existing, _ := db.GetUser(a.DB, username)
	if existing != nil {
		jsonErr(w, http.StatusBadRequest, "Username already taken")
		return
	}

	saltBytes := make([]byte, 32)
	if _, err := cryptoRandRead(saltBytes); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Account creation failed")
		return
	}
	salt := encodeHex(saltBytes)
	hash := auth.HashPassword(body.Password, salt)
	plain, hashes, err := auth.GenerateRecoveryCodes(salt, 8)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Account creation failed")
		return
	}

	if err := db.CreateUser(a.DB, &db.User{
		Username:      username,
		Hash:          hash,
		Salt:          salt,
		TotpSecret:    invite.TotpSecret,
		RecoveryCodes: hashes,
		IsAdmin:       false,
		CreatedAt:     time.Now().UnixMilli(),
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Account creation failed")
		return
	}
	_ = db.DeletePendingInvite(a.DB, body.Token)

	emailPending := false
	if email := strings.TrimSpace(body.Email); email != "" {
		if err := a.sendEmailVerification(r, username, email); err == nil {
			emailPending = true
		}
	}
	jsonOK(w, map[string]any{"ok": true, "recoveryCodes": plain, "emailPending": emailPending})
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func totpSecretResponse(secret, label string) map[string]any {
	uri := fmt.Sprintf("otpauth://totp/AccountManager:%s?secret=%s&issuer=AccountManager",
		url.QueryEscape(label), secret)
	png, _ := qrcode.Encode(uri, qrcode.Medium, 256)

	parts := make([]string, 0)
	for i := 0; i < len(secret); i += 4 {
		end := i + 4
		if end > len(secret) {
			end = len(secret)
		}
		parts = append(parts, secret[i:end])
	}
	return map[string]any{
		"secret":    secret,
		"formatted": strings.Join(parts, " "),
		"qrDataUrl": fmt.Sprintf("data:image/png;base64,%s", encodeBase64(png)),
	}
}
