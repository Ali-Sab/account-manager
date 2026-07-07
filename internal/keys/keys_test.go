package keys

import (
	"os"
	"testing"
)

func TestGenerateAndLoad(t *testing.T) {
	dir := t.TempDir()
	kp, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if kp.Private == nil || kp.Public == nil {
		t.Fatal("Generate returned nil keys")
	}

	// Load should return identical public key modulus.
	kp2, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if kp2.Public.N.Cmp(kp.Public.N) != 0 {
		t.Error("loaded public key does not match generated key")
	}
}

func TestGenerate_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	// Second Generate should overwrite without error.
	if _, err := Generate(dir); err != nil {
		t.Fatalf("second Generate: %v", err)
	}
}

func TestLoad_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Error("expected error loading from empty dir")
	}
}

func TestJWKS_Shape(t *testing.T) {
	dir := t.TempDir()
	kp, _ := Generate(dir)
	jwks := kp.JWKS()

	keysSlice, ok := jwks["keys"].([]map[string]any)
	if !ok || len(keysSlice) == 0 {
		t.Fatal("JWKS missing keys array")
	}
	k := keysSlice[0]
	for _, field := range []string{"kty", "use", "alg", "kid", "n", "e"} {
		if v, ok := k[field]; !ok || v == "" {
			t.Errorf("JWKS key missing field %q", field)
		}
	}
	if k["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %v", k["kty"])
	}
	if k["use"] != "sig" {
		t.Errorf("expected use=sig, got %v", k["use"])
	}
	if k["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got %v", k["alg"])
	}
}

func TestPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	info, err := os.Stat(dir + "/keys/private.pem")
	if err != nil {
		t.Fatalf("stat private.pem: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("private.pem has permissions %v, want 0600", info.Mode().Perm())
	}
}
