package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// waUser implements gowebauthn.User backed by our PasskeyCredential slice.
type waUser struct {
	username string
	id       []byte
	creds    []gowebauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                           { return u.id }
func (u *waUser) WebAuthnName() string                         { return u.username }
func (u *waUser) WebAuthnDisplayName() string                  { return u.username }
func (u *waUser) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

func (a *App) newWebAuthn() (*gowebauthn.WebAuthn, error) {
	return gowebauthn.New(&gowebauthn.Config{
		RPID:          a.Cfg.WebAuthnRPID,
		RPDisplayName: a.Cfg.WebAuthnRPName,
		RPOrigins: []string{
			fmt.Sprintf("https://%s", a.Cfg.WebAuthnRPID),
			fmt.Sprintf("http://%s", a.Cfg.WebAuthnRPID),
		},
	})
}

// passkeysToWACreds converts stored passkeys to go-webauthn Credentials.
func passkeysToWACreds(passkeys []db.PasskeyCredential) []gowebauthn.Credential {
	var out []gowebauthn.Credential
	for _, p := range passkeys {
		raw, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil {
			continue
		}
		idBytes, err := base64.RawURLEncoding.DecodeString(p.CredentialID)
		if err != nil {
			idBytes, _ = base64.StdEncoding.DecodeString(p.CredentialID)
		}
		out = append(out, gowebauthn.Credential{
			ID:        idBytes,
			PublicKey: raw,
			Authenticator: gowebauthn.Authenticator{
				SignCount: uint32(p.Counter),
			},
			Flags: gowebauthn.CredentialFlags{
				BackupEligible: p.BackupEligible,
				BackupState:    p.BackupState,
			},
		})
	}
	return out
}

func credDescriptors(creds []gowebauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(creds))
	for _, c := range creds {
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
		})
	}
	return out
}

// POST /api/webauthn/register/start  (unauthenticated, first-run only)
func (a *App) WebAuthnRegisterStart(w http.ResponseWriter, r *http.Request) {
	count, _ := db.CountUsers(a.DB)
	if count > 0 {
		jsonErr(w, http.StatusForbidden, "Already configured")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" || body.Password == "" {
		jsonErr(w, http.StatusBadRequest, "Missing fields")
		return
	}
	if len(body.Password) < 12 {
		jsonErr(w, http.StatusBadRequest, "Password must be at least 12 characters")
		return
	}

	saltBytes := make([]byte, 32)
	if _, err := cryptoRandRead(saltBytes); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Registration start failed")
		return
	}
	salt := encodeHex(saltBytes)
	hash := auth.HashPassword(body.Password, salt)

	wa, err := a.newWebAuthn()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Registration start failed")
		return
	}
	user := &waUser{username: body.Username, id: []byte(body.Username)}
	creation, session, err := wa.BeginRegistration(user,
		gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Registration start failed")
		return
	}
	if err := db.WriteSetupState(a.DB, &db.SetupState{
		Username:  body.Username,
		Hash:      hash,
		Salt:      salt,
		Challenge: session.Challenge,
		CreatedAt: time.Now().UnixMilli(),
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Registration start failed")
		return
	}
	jsonOK(w, creation)
}

// POST /api/webauthn/register/finish  (unauthenticated, first-run only)
func (a *App) WebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	count, _ := db.CountUsers(a.DB)
	if count > 0 {
		jsonErr(w, http.StatusForbidden, "Already configured")
		return
	}
	state, _ := db.ReadSetupState(a.DB)
	if state == nil || time.Now().UnixMilli()-state.CreatedAt > 10*60*1000 {
		jsonErr(w, http.StatusBadRequest, "Registration session expired")
		return
	}

	wa, err := a.newWebAuthn()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Registration failed")
		return
	}
	user := &waUser{username: state.Username, id: []byte(state.Username)}
	session := gowebauthn.SessionData{
		Challenge:  state.Challenge,
		UserID:     []byte(state.Username),
		CredParams: gowebauthn.CredentialParametersDefault(),
	}

	cred, err := wa.FinishRegistration(user, session, r)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Verification failed")
		return
	}

	if err := db.CreateUser(a.DB, &db.User{
		Username:  state.Username,
		Hash:      state.Hash,
		Salt:      state.Salt,
		TotpSecret: "",
		IsAdmin:   true,
		CreatedAt: time.Now().UnixMilli(),
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Registration failed")
		return
	}
	_ = db.WriteSetupState(a.DB, nil)
	if err := db.WritePasskeyCredential(a.DB, &db.PasskeyCredential{
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		Username:       state.Username,
		PublicKey:      base64.StdEncoding.EncodeToString(cred.PublicKey),
		Counter:        int64(cred.Authenticator.SignCount),
		DeviceName:     "Device 1",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Registration failed")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// POST /api/webauthn/add-device/start  (requireAuth)
func (a *App) WebAuthnAddDeviceStart(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	existing, _ := db.ReadPasskeyCredentialsByUser(a.DB, username)
	wa, err := a.newWebAuthn()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to start")
		return
	}
	waCreds := passkeysToWACreds(existing)
	user := &waUser{
		username: username,
		id:       []byte(username),
		creds:    waCreds,
	}
	creation, session, err := wa.BeginRegistration(user,
		gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		}),
		gowebauthn.WithExclusions(credDescriptors(waCreds)),
	)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to start")
		return
	}
	// Use a per-session nonce so concurrent start calls don't overwrite each other.
	nonce := randomHex(16)
	purpose := "add_device:" + username + ":" + nonce
	if err := db.WriteWebAuthnSession(a.DB, purpose, session.Challenge); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to start")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_add_nonce",
		Value:    nonce,
		HttpOnly: true,
		Secure:   a.Cfg.IsProd,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   600,
	})
	jsonOK(w, creation)
}

// POST /api/webauthn/add-device/finish  (requireAuth)
func (a *App) WebAuthnAddDeviceFinish(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	nonceCookie, err := r.Cookie("wa_add_nonce")
	if err != nil || nonceCookie.Value == "" {
		jsonErr(w, http.StatusBadRequest, "Session expired")
		return
	}
	purpose := "add_device:" + username + ":" + nonceCookie.Value

	state, _ := db.ReadWebAuthnSession(a.DB, purpose)
	if state == nil || time.Now().UnixMilli()-state.CreatedAt > 10*60*1000 {
		jsonErr(w, http.StatusBadRequest, "Session expired")
		return
	}
	existing, _ := db.ReadPasskeyCredentialsByUser(a.DB, username)
	wa, err := a.newWebAuthn()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to register device")
		return
	}
	user := &waUser{username: username, id: []byte(username), creds: passkeysToWACreds(existing)}
	session := gowebauthn.SessionData{
		Challenge:  state.Challenge,
		UserID:     []byte(username),
		CredParams: gowebauthn.CredentialParametersDefault(),
	}

	cred, err := wa.FinishRegistration(user, session, r)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Verification failed")
		return
	}

	deviceName := fmt.Sprintf("Device %d", len(existing)+1)
	if err := db.WritePasskeyCredential(a.DB, &db.PasskeyCredential{
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		Username:       username,
		PublicKey:      base64.StdEncoding.EncodeToString(cred.PublicKey),
		Counter:        int64(cred.Authenticator.SignCount),
		DeviceName:     deviceName,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	}); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to register device")
		return
	}
	_ = db.DeleteWebAuthnSession(a.DB, purpose)
	http.SetCookie(w, &http.Cookie{
		Name:   "wa_add_nonce",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})
	jsonOK(w, map[string]bool{"ok": true})
}

// POST /api/webauthn/login/start
func (a *App) WebAuthnLoginStart(w http.ResponseWriter, r *http.Request) {
	passkeys, _ := db.ReadAllPasskeyCredentials(a.DB)
	if len(passkeys) == 0 {
		jsonErr(w, http.StatusBadRequest, "No passkeys registered")
		return
	}
	wa, err := a.newWebAuthn()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Login start failed")
		return
	}
	assertion, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Login start failed")
		return
	}
	nonce := randomHex(16)
	if err := db.WriteWebAuthnSession(a.DB, "login:"+nonce, session.Challenge); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Login start failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_login_nonce",
		Value:    nonce,
		HttpOnly: true,
		Secure:   a.Cfg.IsProd,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   300,
	})
	jsonOK(w, assertion)
}

// POST /api/webauthn/login/finish
func (a *App) WebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	nonceCookie, err := r.Cookie("wa_login_nonce")
	if err != nil || nonceCookie.Value == "" {
		jsonErr(w, http.StatusBadRequest, "Authentication session expired")
		return
	}
	state, _ := db.ReadWebAuthnSession(a.DB, "login:"+nonceCookie.Value)
	if state == nil || time.Now().UnixMilli()-state.CreatedAt > 5*60*1000 {
		jsonErr(w, http.StatusBadRequest, "Authentication session expired")
		return
	}
	wa, err := a.newWebAuthn()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Authentication failed")
		return
	}

	// FinishDiscoverableLogin resolves the real user from the credential ID,
	// fixing the userHandle mismatch that occurred with the synthetic "_all_" user approach.
	var owner *db.User
	var ownerPasskeys []db.PasskeyCredential
	handler := func(rawID, _ []byte) (gowebauthn.User, error) {
		credID := base64.RawURLEncoding.EncodeToString(rawID)
		u, err := db.GetUserByPasskeyCredentialID(a.DB, credID)
		if err != nil || u == nil {
			return nil, fmt.Errorf("unknown credential")
		}
		owner = u
		ownerPasskeys, _ = db.ReadPasskeyCredentialsByUser(a.DB, u.Username)
		return &waUser{username: u.Username, id: []byte(u.Username), creds: passkeysToWACreds(ownerPasskeys)}, nil
	}

	session := gowebauthn.SessionData{Challenge: state.Challenge}
	updatedCred, err := wa.FinishDiscoverableLogin(handler, session, r)
	if err != nil || owner == nil {
		jsonErr(w, http.StatusUnauthorized, "Authentication failed")
		return
	}

	credID := base64.RawURLEncoding.EncodeToString(updatedCred.ID)
	for _, p := range ownerPasskeys {
		if p.CredentialID == credID {
			p.Counter = int64(updatedCred.Authenticator.SignCount)
			p.BackupState = updatedCred.Flags.BackupState
			_ = db.WritePasskeyCredential(a.DB, &p)
			break
		}
	}
	_ = db.DeleteWebAuthnSession(a.DB, "login:"+nonceCookie.Value)
	http.SetCookie(w, &http.Cookie{
		Name:   "wa_login_nonce",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})

	accessToken, csrfToken, err := a.issueSession(w, r, owner.Username)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Authentication failed")
		return
	}
	jsonOK(w, map[string]string{"accessToken": accessToken, "csrfToken": csrfToken})
}

// GET /api/webauthn/credentials  (requireAuth)
func (a *App) WebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	passkeys, _ := db.ReadPasskeyCredentialsByUser(a.DB, username)
	type view struct {
		CredentialID string `json:"credentialId"`
		DeviceName   string `json:"deviceName"`
		CreatedAt    string `json:"createdAt"`
	}
	out := make([]view, 0, len(passkeys))
	for _, p := range passkeys {
		out = append(out, view{CredentialID: p.CredentialID, DeviceName: p.DeviceName, CreatedAt: p.CreatedAt})
	}
	jsonOK(w, out)
}

// DELETE /api/webauthn/credentials/:id  (requireAuth)
func (a *App) WebAuthnDeleteCredential(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	id := chi.URLParam(r, "id")
	if err := db.DeletePasskeyCredentialForUser(a.DB, id, username); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to delete credential")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

