package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

type KeyPair struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
}

func Load(dataDir string) (*KeyPair, error) {
	privPath := filepath.Join(dataDir, "keys", "private.pem")
	pubPath := filepath.Join(dataDir, "keys", "public.pem")

	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("private key not found at %s — run setup first: %w", privPath, err)
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("public key not found at %s — run setup first: %w", pubPath, err)
	}

	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		// fall back to PKCS1
		privKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}
	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	return &KeyPair{Private: rsaPriv, Public: rsaPub}, nil
}

// Generate creates a new RSA-2048 keypair and writes PEM files to DATA_DIR/keys/.
func Generate(dataDir string) (*KeyPair, error) {
	dir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(filepath.Join(dir, "private.pem"), privPEM, 0600); err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(filepath.Join(dir, "public.pem"), pubPEM, 0644); err != nil {
		return nil, err
	}

	return &KeyPair{Private: priv, Public: &priv.PublicKey}, nil
}

// JWKS returns the JSON Web Key Set representation of the public key.
func (kp *KeyPair) JWKS() map[string]any {
	pub := kp.Public
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": "account-manager-key",
				"n":   n,
				"e":   e,
			},
		},
	}
}
