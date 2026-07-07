package auth

import (
	"testing"
)

func TestHashPassword_Deterministic(t *testing.T) {
	h1 := HashPassword("mysecret", "somesalt")
	h2 := HashPassword("mysecret", "somesalt")
	if h1 != h2 {
		t.Fatalf("same inputs produced different hashes: %s vs %s", h1, h2)
	}
}

func TestHashPassword_DifferentSalt(t *testing.T) {
	h1 := HashPassword("mysecret", "salt1")
	h2 := HashPassword("mysecret", "salt2")
	if h1 == h2 {
		t.Fatalf("different salts produced same hash")
	}
}

func TestHashPassword_DifferentPassword(t *testing.T) {
	h1 := HashPassword("password1", "salt")
	h2 := HashPassword("password2", "salt")
	if h1 == h2 {
		t.Fatalf("different passwords produced same hash")
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	h := HashPassword("", "salt")
	if h == "" {
		t.Fatal("empty password produced empty hash")
	}
	// Must not equal a non-empty password with same salt.
	h2 := HashPassword("x", "salt")
	if h == h2 {
		t.Fatal("empty and non-empty password collide")
	}
}

func TestHashPassword_Length(t *testing.T) {
	h := HashPassword("test", "salt")
	// 64 bytes hex-encoded = 128 chars.
	if len(h) != 128 {
		t.Fatalf("expected 128-char hex, got %d", len(h))
	}
}
