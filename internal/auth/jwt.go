package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwt.RegisteredClaims
	MFAPending bool `json:"mfaPending,omitempty"`
}

// SignToken issues an RS256 JWT. duration is a Go time.Duration (e.g. time.Hour).
func SignToken(priv *rsa.PrivateKey, issuer, sub, audience string, duration time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{audience},
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(priv)
}

// VerifyAccess validates a token for the account-manager audience.
func VerifyAccess(pub *rsa.PublicKey, issuer, tokenStr string) (*Claims, error) {
	return parseToken(pub, issuer, "account-manager", tokenStr)
}

// SignMFAToken issues a short-lived step token (5 min) with mfaPending=true.
func SignMFAToken(priv *rsa.PrivateKey, issuer, username string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		MFAPending: true,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(priv)
}

// VerifyMFAToken validates an MFA step token and returns claims if mfaPending is set.
func VerifyMFAToken(pub *rsa.PublicKey, issuer, tokenStr string) (*Claims, error) {
	p := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	claims := &Claims{}
	_, err := p.ParseWithClaims(tokenStr, claims, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil {
		return nil, err
	}
	if !claims.MFAPending {
		return nil, fmt.Errorf("not an MFA token")
	}
	return claims, nil
}

// SignLogoutToken issues a short-lived backchannel logout token (OIDC Back-Channel Logout).
// Clients verify the signature and the presence of the backchannel-logout event claim.
func SignLogoutToken(priv *rsa.PrivateKey, issuer, subject string) (string, error) {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", err
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": fmt.Sprintf("%x", jtiBytes),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return t.SignedString(priv)
}

func parseToken(pub *rsa.PublicKey, issuer, audience, tokenStr string) (*Claims, error) {
	p := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
	)
	claims := &Claims{}
	_, err := p.ParseWithClaims(tokenStr, claims, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil {
		return nil, err
	}
	return claims, nil
}
