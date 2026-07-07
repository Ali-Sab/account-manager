package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewRecoveryCode generates a single recovery code in xxxx-xxxx-xx format (10 hex chars).
func NewRecoveryCode() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s", raw[0:4], raw[4:8], raw[8:10]), nil
}

// GenerateRecoveryCodes produces n plaintext codes and their PBKDF2 hashes.
func GenerateRecoveryCodes(salt string, n int) (plain []string, hashes []string, err error) {
	for i := 0; i < n; i++ {
		code, e := NewRecoveryCode()
		if e != nil {
			return nil, nil, e
		}
		plain = append(plain, code)
		hashes = append(hashes, HashPassword(code, salt))
	}
	return plain, hashes, nil
}
