package auth

import (
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateSecret creates a new base32 TOTP secret (20 bytes = 160 bits).
func GenerateSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AccountManager",
		AccountName: "setup",
		SecretSize:  20,
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

// VerifyTOTP checks a 6-digit TOTP code with ±1 period tolerance.
func VerifyTOTP(secret, code string) bool {
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != 6 {
		return false
	}
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}
