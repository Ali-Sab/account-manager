package db

import (
	"database/sql"
	"encoding/json"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

type User struct {
	ID            int64
	Username      string
	Email         string
	Hash          string
	Salt          string
	TotpSecret    string
	RecoveryCodes []string
	IsAdmin       bool
	CreatedAt     int64
}

type RefreshToken struct {
	Token     string
	ExpiresAt int64
}

type PendingSetup struct {
	Secret    string
	CreatedAt int64
}

type PasskeyCredential struct {
	CredentialID   string
	Username       string
	PublicKey      string
	Counter        int64
	DeviceName     string
	CreatedAt      string
	BackupEligible bool
	BackupState    bool
}

type WebAuthnChallenge struct {
	Challenge string
	CreatedAt int64
}

type SetupState struct {
	Username  string
	Hash      string
	Salt      string
	Challenge string
	CreatedAt int64
}

type OAuthClient struct {
	ClientID             string
	ClientSecretHash     string
	ClientSecret         string // plaintext, stored only for display purposes (e.g. MCP credentials page)
	RedirectURIs         []string
	Name                 string
	Audience             string
	BackchannelLogoutURI string
}

type OAuthAuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           int64
	Username            string
}

type OAuthRefreshToken struct {
	ClientID  string
	Username  string
	ExpiresAt int64
}

type PendingInvite struct {
	Token      string
	InvitedBy  string
	TotpSecret string
	CreatedAt  int64
}

// ─── Users ────────────────────────────────────────────────────────────────────

func GetUser(db *sql.DB, username string) (*User, error) {
	row := db.QueryRow(`
		SELECT id, username, email, hash, salt, totp_secret, recovery_codes, is_admin, created_at
		FROM users WHERE username = ?`, username)
	return scanUser(row)
}

func CountUsers(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

func CountAdmins(db *sql.DB) (int, error) {
	var n int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&n)
	return n, err
}

func ListUsers(db *sql.DB) ([]*User, error) {
	rows, err := db.Query(`
		SELECT id, username, email, hash, salt, totp_secret, recovery_codes, is_admin, created_at
		FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func CreateUser(db *sql.DB, u *User) error {
	codes, _ := json.Marshal(u.RecoveryCodes)
	isAdmin := 0
	if u.IsAdmin {
		isAdmin = 1
	}
	_, err := db.Exec(`
		INSERT INTO users (username, email, hash, salt, totp_secret, recovery_codes, is_admin, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.Email, u.Hash, u.Salt, u.TotpSecret, string(codes), isAdmin, u.CreatedAt)
	return err
}

func UpdateUser(db *sql.DB, u *User) error {
	codes, _ := json.Marshal(u.RecoveryCodes)
	isAdmin := 0
	if u.IsAdmin {
		isAdmin = 1
	}
	_, err := db.Exec(`
		UPDATE users SET email=?, hash=?, salt=?, totp_secret=?, recovery_codes=?, is_admin=?
		WHERE username=?`,
		u.Email, u.Hash, u.Salt, u.TotpSecret, string(codes), isAdmin, u.Username)
	return err
}

func UpdateUserEmail(db *sql.DB, username, email string) error {
	_, err := db.Exec("UPDATE users SET email=? WHERE username=?", email, username)
	return err
}

func GetUserByEmail(db *sql.DB, email string) (*User, error) {
	if email == "" {
		return nil, nil
	}
	row := db.QueryRow(`
		SELECT id, username, email, hash, salt, totp_secret, recovery_codes, is_admin, created_at
		FROM users WHERE email = ?`, email)
	return scanUser(row)
}

func DeleteUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

func scanUser(s interface {
	Scan(...any) error
}) (*User, error) {
	var u User
	var codes sql.NullString
	var isAdmin int
	if err := s.Scan(&u.ID, &u.Username, &u.Email, &u.Hash, &u.Salt, &u.TotpSecret, &codes, &isAdmin, &u.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	u.IsAdmin = isAdmin == 1
	if codes.Valid && codes.String != "" {
		_ = json.Unmarshal([]byte(codes.String), &u.RecoveryCodes)
	}
	return &u, nil
}

// ─── Refresh tokens ───────────────────────────────────────────────────────────

func SaveRefreshToken(db *sql.DB, token string, expiresAt int64, username string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO refresh_tokens (token, expires_at, username) VALUES (?, ?, ?)", token, expiresAt, username)
	return err
}

// ValidateRefreshToken returns the username and whether the token is valid.
func ValidateRefreshToken(db *sql.DB, token string) (username string, ok bool) {
	var exp int64
	var uname string
	err := db.QueryRow("SELECT expires_at, username FROM refresh_tokens WHERE token = ?", token).Scan(&exp, &uname)
	if err != nil || exp <= time.Now().UnixMilli() {
		return "", false
	}
	return uname, true
}

func RevokeRefreshToken(db *sql.DB, token string) error {
	_, err := db.Exec("DELETE FROM refresh_tokens WHERE token = ?", token)
	return err
}

func DeleteAllRefreshTokens(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM refresh_tokens")
	return err
}

func DeleteRefreshTokensByUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM refresh_tokens WHERE username = ?", username)
	return err
}

func PruneExpiredRefreshTokens(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM refresh_tokens WHERE expires_at < ?", time.Now().UnixMilli())
	return err
}

// ─── Pending setup ────────────────────────────────────────────────────────────

func ReadPendingSetup(db *sql.DB) (*PendingSetup, error) {
	var p PendingSetup
	err := db.QueryRow("SELECT secret, created_at FROM pending_setup WHERE id = 1").Scan(&p.Secret, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &p, err
}

func WritePendingSetup(db *sql.DB, p *PendingSetup) error {
	if p == nil {
		_, err := db.Exec("DELETE FROM pending_setup WHERE id = 1")
		return err
	}
	_, err := db.Exec(`
		INSERT INTO pending_setup (id, secret, created_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET secret=excluded.secret, created_at=excluded.created_at`,
		p.Secret, p.CreatedAt)
	return err
}

// ─── Passkey credentials ──────────────────────────────────────────────────────

func ReadPasskeyCredentialsByUser(db *sql.DB, username string) ([]PasskeyCredential, error) {
	rows, err := db.Query(`
		SELECT credential_id, username, public_key, counter, device_name, created_at, backup_eligible, backup_state
		FROM passkey_credentials WHERE username = ?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPasskeys(rows)
}

func ReadAllPasskeyCredentials(db *sql.DB) ([]PasskeyCredential, error) {
	rows, err := db.Query(`
		SELECT credential_id, username, public_key, counter, device_name, created_at, backup_eligible, backup_state
		FROM passkey_credentials`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPasskeys(rows)
}

// ReadPasskeyCredentials is kept for backward compatibility with existing tests.
func ReadPasskeyCredentials(db *sql.DB) ([]PasskeyCredential, error) {
	return ReadAllPasskeyCredentials(db)
}

func GetUserByPasskeyCredentialID(db *sql.DB, credentialID string) (*User, error) {
	var username string
	err := db.QueryRow("SELECT username FROM passkey_credentials WHERE credential_id = ?", credentialID).Scan(&username)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return GetUser(db, username)
}

func scanPasskeys(rows *sql.Rows) ([]PasskeyCredential, error) {
	var out []PasskeyCredential
	for rows.Next() {
		var p PasskeyCredential
		var name sql.NullString
		if err := rows.Scan(&p.CredentialID, &p.Username, &p.PublicKey, &p.Counter, &name, &p.CreatedAt, &p.BackupEligible, &p.BackupState); err != nil {
			return nil, err
		}
		p.DeviceName = name.String
		out = append(out, p)
	}
	return out, rows.Err()
}

func WritePasskeyCredential(db *sql.DB, p *PasskeyCredential) error {
	_, err := db.Exec(`
		INSERT INTO passkey_credentials (credential_id, username, public_key, counter, device_name, created_at, backup_eligible, backup_state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(credential_id) DO UPDATE SET
			username=excluded.username, public_key=excluded.public_key, counter=excluded.counter,
			device_name=excluded.device_name, backup_state=excluded.backup_state`,
		p.CredentialID, p.Username, p.PublicKey, p.Counter, nullStr(p.DeviceName), p.CreatedAt, p.BackupEligible, p.BackupState)
	return err
}

func DeletePasskeyCredential(db *sql.DB, credentialID string) error {
	_, err := db.Exec("DELETE FROM passkey_credentials WHERE credential_id = ?", credentialID)
	return err
}

func DeletePasskeyCredentialForUser(db *sql.DB, credentialID, username string) error {
	_, err := db.Exec("DELETE FROM passkey_credentials WHERE credential_id = ? AND username = ?", credentialID, username)
	return err
}

func DeleteAllPasskeysByUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM passkey_credentials WHERE username = ?", username)
	return err
}

func DeleteOAuthRefreshTokensByUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM oauth_refresh_tokens WHERE username = ?", username)
	return err
}

func DeleteOAuthAuthCodesByUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM oauth_auth_codes WHERE username = ?", username)
	return err
}

// ─── WebAuthn sessions ────────────────────────────────────────────────────────

func WriteWebAuthnSession(db *sql.DB, purpose, challenge string) error {
	_, err := db.Exec(`
		INSERT INTO webauthn_sessions (purpose, challenge, created_at) VALUES (?, ?, ?)
		ON CONFLICT(purpose) DO UPDATE SET challenge=excluded.challenge, created_at=excluded.created_at`,
		purpose, challenge, time.Now().UnixMilli())
	return err
}

func ReadWebAuthnSession(db *sql.DB, purpose string) (*WebAuthnChallenge, error) {
	var c WebAuthnChallenge
	err := db.QueryRow("SELECT challenge, created_at FROM webauthn_sessions WHERE purpose = ?", purpose).Scan(&c.Challenge, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func DeleteWebAuthnSession(db *sql.DB, purpose string) error {
	_, err := db.Exec("DELETE FROM webauthn_sessions WHERE purpose = ?", purpose)
	return err
}

// Legacy webauthn_challenges functions kept for any remaining callers.

func ReadWebAuthnChallenge(db *sql.DB) (*WebAuthnChallenge, error) {
	var c WebAuthnChallenge
	err := db.QueryRow("SELECT challenge, created_at FROM webauthn_challenges WHERE id = 1").Scan(&c.Challenge, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &c, err
}

func WriteWebAuthnChallenge(db *sql.DB, c *WebAuthnChallenge) error {
	if c == nil {
		_, err := db.Exec("DELETE FROM webauthn_challenges WHERE id = 1")
		return err
	}
	_, err := db.Exec(`
		INSERT INTO webauthn_challenges (id, challenge, created_at) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET challenge=excluded.challenge, created_at=excluded.created_at`,
		c.Challenge, c.CreatedAt)
	return err
}

// ─── Setup state ──────────────────────────────────────────────────────────────

func ReadSetupState(db *sql.DB) (*SetupState, error) {
	var s SetupState
	err := db.QueryRow("SELECT username, hash, salt, challenge, created_at FROM setup_state WHERE id = 1").
		Scan(&s.Username, &s.Hash, &s.Salt, &s.Challenge, &s.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &s, err
}

func WriteSetupState(db *sql.DB, s *SetupState) error {
	if s == nil {
		_, err := db.Exec("DELETE FROM setup_state WHERE id = 1")
		return err
	}
	_, err := db.Exec(`
		INSERT INTO setup_state (id, username, hash, salt, challenge, created_at)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			username=excluded.username, hash=excluded.hash, salt=excluded.salt,
			challenge=excluded.challenge, created_at=excluded.created_at`,
		s.Username, s.Hash, s.Salt, s.Challenge, s.CreatedAt)
	return err
}

// ─── OAuth clients ────────────────────────────────────────────────────────────

// AllOAuthRedirectURIs returns every redirect URI registered across all OAuth clients.
func AllOAuthRedirectURIs(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT redirect_uris FROM oauth_clients")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var uris []string
		if err := json.Unmarshal([]byte(raw), &uris); err == nil {
			all = append(all, uris...)
		}
	}
	return all, rows.Err()
}

func GetOAuthClient(db *sql.DB, clientID string) (*OAuthClient, error) {
	var c OAuthClient
	var uris string
	err := db.QueryRow(`SELECT client_id, client_secret_hash, COALESCE(client_secret,''), redirect_uris,
		COALESCE(name,''), audience, COALESCE(backchannel_logout_uri,'')
		FROM oauth_clients WHERE client_id = ?`, clientID).
		Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientSecret, &uris, &c.Name, &c.Audience, &c.BackchannelLogoutURI)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	return &c, nil
}

// GetBackchannelLogoutURIsForUser returns the backchannel_logout_uri for each
// OAuth client that currently holds an active refresh token for username.
func GetBackchannelLogoutURIsForUser(db *sql.DB, username string) ([]string, error) {
	rows, err := db.Query(`
		SELECT DISTINCT c.backchannel_logout_uri
		FROM oauth_clients c
		JOIN oauth_refresh_tokens t ON c.client_id = t.client_id
		WHERE t.username = ? AND c.backchannel_logout_uri != ''`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, err
		}
		uris = append(uris, uri)
	}
	return uris, rows.Err()
}

func UpsertOAuthClient(db *sql.DB, c *OAuthClient) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	_, err := db.Exec(`
		INSERT INTO oauth_clients (client_id, client_secret_hash, client_secret, redirect_uris, name, audience, backchannel_logout_uri)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(client_id) DO UPDATE SET
			client_secret_hash=excluded.client_secret_hash,
			client_secret=excluded.client_secret,
			redirect_uris=excluded.redirect_uris,
			name=excluded.name,
			audience=excluded.audience,
			backchannel_logout_uri=excluded.backchannel_logout_uri`,
		c.ClientID, c.ClientSecretHash, c.ClientSecret, string(uris), nullStr(c.Name), c.Audience, c.BackchannelLogoutURI)
	return err
}

// ─── OAuth auth codes ─────────────────────────────────────────────────────────

func SaveOAuthAuthCode(db *sql.DB, code, clientID, redirectURI, codeChallenge, codeChallengeMethod string, expiresAt int64, username string) error {
	_, err := db.Exec(`
		INSERT INTO oauth_auth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, expires_at, used, username)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
		code, clientID, redirectURI, nullStr(codeChallenge), nullStr(codeChallengeMethod), expiresAt, username)
	return err
}

func GetAndConsumeOAuthAuthCode(db *sql.DB, code string) (*OAuthAuthCode, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var a OAuthAuthCode
	var challenge, method sql.NullString
	err = tx.QueryRow(`
		SELECT code, client_id, redirect_uri, code_challenge, code_challenge_method, expires_at, username
		FROM oauth_auth_codes WHERE code = ? AND used = 0`, code).
		Scan(&a.Code, &a.ClientID, &a.RedirectURI, &challenge, &method, &a.ExpiresAt, &a.Username)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.CodeChallenge = challenge.String
	a.CodeChallengeMethod = method.String

	if _, err = tx.Exec("UPDATE oauth_auth_codes SET used = 1 WHERE code = ?", code); err != nil {
		return nil, err
	}
	return &a, tx.Commit()
}

// ─── OAuth refresh tokens ─────────────────────────────────────────────────────

func SaveOAuthRefreshToken(db *sql.DB, tokenHash, clientID string, expiresAt int64, username string) error {
	_, err := db.Exec("INSERT INTO oauth_refresh_tokens (token_hash, client_id, expires_at, username) VALUES (?, ?, ?, ?)",
		tokenHash, clientID, expiresAt, username)
	return err
}

func GetAndRotateOAuthRefreshToken(db *sql.DB, tokenHash string) (*OAuthRefreshToken, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck

	var r OAuthRefreshToken
	err = tx.QueryRow(`
		SELECT client_id, username, expires_at FROM oauth_refresh_tokens
		WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, time.Now().UnixMilli()).Scan(&r.ClientID, &r.Username, &r.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec("DELETE FROM oauth_refresh_tokens WHERE token_hash = ?", tokenHash)
	if err != nil {
		return nil, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return nil, nil
	}
	return &r, tx.Commit()
}

// ─── Pending invites ──────────────────────────────────────────────────────────

func CreatePendingInvite(db *sql.DB, token, invitedBy string) error {
	_, err := db.Exec(
		"INSERT INTO pending_invites (token, invited_by, created_at) VALUES (?, ?, ?)",
		token, invitedBy, time.Now().UnixMilli())
	return err
}

func GetPendingInvite(db *sql.DB, token string) (*PendingInvite, error) {
	var p PendingInvite
	var secret sql.NullString
	err := db.QueryRow(
		"SELECT token, invited_by, totp_secret, created_at FROM pending_invites WHERE token = ?", token).
		Scan(&p.Token, &p.InvitedBy, &secret, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.TotpSecret = secret.String
	return &p, nil
}

func SetPendingInviteSecret(db *sql.DB, token, totpSecret string) error {
	_, err := db.Exec("UPDATE pending_invites SET totp_secret = ? WHERE token = ?", totpSecret, token)
	return err
}

func DeletePendingInvite(db *sql.DB, token string) error {
	_, err := db.Exec("DELETE FROM pending_invites WHERE token = ?", token)
	return err
}

// ─── Password reset tokens ────────────────────────────────────────────────────

func SavePasswordResetToken(db *sql.DB, token, username string, expiresAt int64) error {
	_, err := db.Exec(
		"INSERT INTO password_reset_tokens (token, username, expires_at, created_at) VALUES (?, ?, ?, ?)",
		token, username, expiresAt, time.Now().UnixMilli())
	return err
}

// GetPasswordResetToken validates a reset token and returns the username if valid and unexpired.
// The token is NOT consumed here — call DeletePasswordResetTokensByUser after a successful reset.
func GetPasswordResetToken(db *sql.DB, token string) (string, bool) {
	var username string
	var expiresAt int64
	err := db.QueryRow(
		"SELECT username, expires_at FROM password_reset_tokens WHERE token = ?", token).
		Scan(&username, &expiresAt)
	if err != nil || time.Now().UnixMilli() > expiresAt {
		return "", false
	}
	return username, true
}

func DeletePasswordResetTokensByUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM password_reset_tokens WHERE username = ?", username)
	return err
}

// ─── Email verification tokens ────────────────────────────────────────────────

func SaveEmailVerificationToken(db *sql.DB, token, username, email string, expiresAt int64) error {
	_, _ = db.Exec("DELETE FROM email_verification_tokens WHERE username = ?", username)
	_, err := db.Exec(
		"INSERT INTO email_verification_tokens (token, username, email, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		token, username, email, expiresAt, time.Now().UnixMilli())
	return err
}

func GetAndConsumeEmailVerificationToken(db *sql.DB, token string) (username, email string, ok bool) {
	tx, err := db.Begin()
	if err != nil {
		return "", "", false
	}
	defer tx.Rollback() //nolint:errcheck

	var expiresAt int64
	err = tx.QueryRow(
		"SELECT username, email, expires_at FROM email_verification_tokens WHERE token = ?", token).
		Scan(&username, &email, &expiresAt)
	if err != nil || time.Now().UnixMilli() > expiresAt {
		return "", "", false
	}
	result, err := tx.Exec("DELETE FROM email_verification_tokens WHERE token = ?", token)
	if err != nil {
		return "", "", false
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return "", "", false
	}
	if err := tx.Commit(); err != nil {
		return "", "", false
	}
	return username, email, true
}

func GetPendingEmailVerification(db *sql.DB, username string) (string, bool) {
	var email string
	var expiresAt int64
	err := db.QueryRow(
		"SELECT email, expires_at FROM email_verification_tokens WHERE username = ?", username).
		Scan(&email, &expiresAt)
	if err != nil || time.Now().UnixMilli() > expiresAt {
		return "", false
	}
	return email, true
}

func DeleteEmailVerificationsByUser(db *sql.DB, username string) error {
	_, err := db.Exec("DELETE FROM email_verification_tokens WHERE username = ?", username)
	return err
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func nullStr(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
