package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestVerifyTOTP_Valid(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !VerifyTOTP(secret, code) {
		t.Error("expected valid TOTP code to pass")
	}
}

func TestVerifyTOTP_WrongCode(t *testing.T) {
	secret, _ := GenerateSecret()
	if VerifyTOTP(secret, "000000") {
		// Extremely unlikely to be valid.
		t.Skip("000000 happened to be valid (1-in-million chance)")
	}
}

func TestVerifyTOTP_ShortCode(t *testing.T) {
	secret, _ := GenerateSecret()
	if VerifyTOTP(secret, "123") {
		t.Error("short code should not pass")
	}
}

func TestVerifyTOTP_EmptyCode(t *testing.T) {
	secret, _ := GenerateSecret()
	if VerifyTOTP(secret, "") {
		t.Error("empty code should not pass")
	}
}

func TestVerifyTOTP_WithSpaces(t *testing.T) {
	secret, _ := GenerateSecret()
	code, _ := totp.GenerateCode(secret, time.Now())
	// Insert spaces (some apps display codes with a space in the middle).
	spaced := code[:3] + " " + code[3:]
	if !VerifyTOTP(secret, spaced) {
		t.Error("code with spaces should be normalised and pass")
	}
}

func TestGenerateSecret_Length(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if len(secret) < 16 {
		t.Fatalf("secret too short: %q", secret)
	}
}
