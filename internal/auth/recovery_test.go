package auth

import (
	"regexp"
	"testing"
)

var recoveryCodeFormat = regexp.MustCompile(`^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{2}$`)

func TestNewRecoveryCode_Format(t *testing.T) {
	for i := 0; i < 20; i++ {
		code, err := NewRecoveryCode()
		if err != nil {
			t.Fatalf("NewRecoveryCode: %v", err)
		}
		if !recoveryCodeFormat.MatchString(code) {
			t.Errorf("code %q does not match expected format xxxx-xxxx-xx", code)
		}
	}
}

func TestNewRecoveryCode_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, _ := NewRecoveryCode()
		if seen[code] {
			t.Fatalf("duplicate recovery code: %s", code)
		}
		seen[code] = true
	}
}

func TestGenerateRecoveryCodes_Count(t *testing.T) {
	plain, hashes, err := GenerateRecoveryCodes("testsalt", 8)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(plain) != 8 {
		t.Errorf("expected 8 plain codes, got %d", len(plain))
	}
	if len(hashes) != 8 {
		t.Errorf("expected 8 hashes, got %d", len(hashes))
	}
}

func TestGenerateRecoveryCodes_HashRoundTrip(t *testing.T) {
	salt := "roundtripsalt"
	plain, hashes, err := GenerateRecoveryCodes(salt, 4)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	for i, code := range plain {
		expected := HashPassword(code, salt)
		if hashes[i] != expected {
			t.Errorf("hash[%d] mismatch: got %s, want %s", i, hashes[i], expected)
		}
	}
}
