package auth

import (
	"crypto/sha512"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

// HashPassword matches the Node.js implementation: PBKDF2-SHA512, 310000 iterations, 64-byte key, hex output.
func HashPassword(password, salt string) string {
	key := pbkdf2.Key([]byte(password), []byte(salt), 310000, 64, sha512.New)
	return hex.EncodeToString(key)
}
