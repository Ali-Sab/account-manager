package db

import (
	"database/sql"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open in-memory DB: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	return sqlDB
}

// ─── Refresh tokens ───────────────────────────────────────────────────────────

func TestRefreshToken_SaveValidRevoke(t *testing.T) {
	db := openTestDB(t)
	future := time.Now().Add(time.Hour).UnixMilli()

	if err := SaveRefreshToken(db, "tok1", future, "alice"); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	_, ok := ValidateRefreshToken(db, "tok1")
	if !ok {
		t.Error("expected valid token")
	}

	if err := RevokeRefreshToken(db, "tok1"); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}
	_, ok = ValidateRefreshToken(db, "tok1")
	if ok {
		t.Error("revoked token still valid")
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	db := openTestDB(t)
	past := time.Now().Add(-time.Hour).UnixMilli()
	SaveRefreshToken(db, "expired", past, "alice") //nolint:errcheck
	_, ok := ValidateRefreshToken(db, "expired")
	if ok {
		t.Error("expired token should not be valid")
	}
}

func TestRefreshToken_DeleteAll(t *testing.T) {
	db := openTestDB(t)
	future := time.Now().Add(time.Hour).UnixMilli()
	SaveRefreshToken(db, "t1", future, "alice") //nolint:errcheck
	SaveRefreshToken(db, "t2", future, "alice") //nolint:errcheck
	DeleteAllRefreshTokens(db)                  //nolint:errcheck
	for _, tok := range []string{"t1", "t2"} {
		_, ok := ValidateRefreshToken(db, tok)
		if ok {
			t.Errorf("token %s should be deleted", tok)
		}
	}
}

// ─── Passkey credentials ──────────────────────────────────────────────────────

func TestPasskeyCredential_CRUD(t *testing.T) {
	db := openTestDB(t)
	all, _ := ReadPasskeyCredentials(db)
	if len(all) != 0 {
		t.Fatal("expected no passkeys on fresh DB")
	}

	p := &PasskeyCredential{
		CredentialID: "cred1",
		PublicKey:    "pubkeybase64",
		Counter:      0,
		DeviceName:   "MacBook",
		CreatedAt:    "2024-01-01T00:00:00Z",
	}
	if err := WritePasskeyCredential(db, p); err != nil {
		t.Fatalf("WritePasskeyCredential: %v", err)
	}

	all, _ = ReadPasskeyCredentials(db)
	if len(all) != 1 {
		t.Fatalf("expected 1 passkey, got %d", len(all))
	}
	if all[0].CredentialID != "cred1" {
		t.Errorf("credential ID mismatch")
	}

	// Update counter.
	p.Counter = 5
	WritePasskeyCredential(db, p) //nolint:errcheck
	all, _ = ReadPasskeyCredentials(db)
	if all[0].Counter != 5 {
		t.Errorf("expected counter 5, got %d", all[0].Counter)
	}

	// Delete.
	DeletePasskeyCredential(db, "cred1") //nolint:errcheck
	all, _ = ReadPasskeyCredentials(db)
	if len(all) != 0 {
		t.Errorf("expected 0 passkeys after delete, got %d", len(all))
	}
}

// ─── OAuth auth codes ─────────────────────────────────────────────────────────

func TestOAuthAuthCode_SaveConsume(t *testing.T) {
	db := openTestDB(t)
	expires := time.Now().Add(5 * time.Minute).UnixMilli()
	SaveOAuthAuthCode(db, "code1", "client1", "https://example.com/cb", "challenge", "S256", expires, "alice") //nolint:errcheck

	record, err := GetAndConsumeOAuthAuthCode(db, "code1")
	if err != nil || record == nil {
		t.Fatalf("GetAndConsumeOAuthAuthCode: %v %v", record, err)
	}
	if record.ClientID != "client1" {
		t.Errorf("expected client1, got %s", record.ClientID)
	}

	// Second consume should return nil (single-use).
	record2, _ := GetAndConsumeOAuthAuthCode(db, "code1")
	if record2 != nil {
		t.Error("code should be consumed and return nil on second call")
	}
}

func TestOAuthAuthCode_NotFound(t *testing.T) {
	db := openTestDB(t)
	record, err := GetAndConsumeOAuthAuthCode(db, "nonexistent")
	if err != nil || record != nil {
		t.Errorf("expected nil record for unknown code, got %v %v", record, err)
	}
}

// ─── OAuth refresh tokens ─────────────────────────────────────────────────────

func TestOAuthRefreshToken_Rotation(t *testing.T) {
	db := openTestDB(t)
	expires := time.Now().Add(time.Hour).UnixMilli()
	SaveOAuthRefreshToken(db, "hash1", "client1", expires, "alice") //nolint:errcheck

	record, err := GetAndRotateOAuthRefreshToken(db, "hash1")
	if err != nil || record == nil {
		t.Fatalf("GetAndRotateOAuthRefreshToken: %v %v", record, err)
	}
	if record.ClientID != "client1" {
		t.Errorf("expected client1, got %s", record.ClientID)
	}

	// After rotation the old hash should be gone.
	record2, _ := GetAndRotateOAuthRefreshToken(db, "hash1")
	if record2 != nil {
		t.Error("old token hash should be deleted after rotation")
	}
}

func TestOAuthRefreshToken_Expired(t *testing.T) {
	db := openTestDB(t)
	past := time.Now().Add(-time.Hour).UnixMilli()
	SaveOAuthRefreshToken(db, "oldhash", "client1", past, "alice") //nolint:errcheck
	record, _ := GetAndRotateOAuthRefreshToken(db, "oldhash")
	if record != nil {
		t.Error("expired token should not be returned")
	}
}

// ─── OAuth clients ────────────────────────────────────────────────────────────

func TestOAuthClient_UpsertGet(t *testing.T) {
	db := openTestDB(t)
	c := &OAuthClient{
		ClientID:         "test-client",
		ClientSecretHash: "secrethash",
		RedirectURIs:     []string{"https://example.com/cb"},
		Name:             "Test",
		Audience:         "mcp",
	}
	if err := UpsertOAuthClient(db, c); err != nil {
		t.Fatalf("UpsertOAuthClient: %v", err)
	}

	got, err := GetOAuthClient(db, "test-client")
	if err != nil || got == nil {
		t.Fatalf("GetOAuthClient: %v %v", got, err)
	}
	if got.ClientSecretHash != "secrethash" {
		t.Errorf("secret hash mismatch")
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://example.com/cb" {
		t.Errorf("redirect URIs mismatch: %v", got.RedirectURIs)
	}
}

func TestOAuthClient_NotFound(t *testing.T) {
	db := openTestDB(t)
	got, err := GetOAuthClient(db, "nonexistent")
	if err != nil || got != nil {
		t.Errorf("expected nil for unknown client, got %v %v", got, err)
	}
}

// ─── WebAuthn challenge ───────────────────────────────────────────────────────

func TestWebAuthnChallenge_WriteReadClear(t *testing.T) {
	db := openTestDB(t)

	c, _ := ReadWebAuthnChallenge(db)
	if c != nil {
		t.Fatal("expected nil on fresh DB")
	}

	WriteWebAuthnChallenge(db, &WebAuthnChallenge{Challenge: "abc", CreatedAt: 12345}) //nolint:errcheck
	c, _ = ReadWebAuthnChallenge(db)
	if c == nil || c.Challenge != "abc" {
		t.Errorf("challenge mismatch: %v", c)
	}

	WriteWebAuthnChallenge(db, nil) //nolint:errcheck
	c, _ = ReadWebAuthnChallenge(db)
	if c != nil {
		t.Error("expected nil after clear")
	}
}
