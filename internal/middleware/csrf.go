package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

const (
	csrfCookie = "csrf_token"
	csrfHeader = "X-CSRF-Token"
)

// GenerateCSRFToken creates a new CSRF cookie+token pair and returns the token the client
// should send back in the X-CSRF-Token header. Call this from GET /api/auth/csrf.
func GenerateCSRFToken(w http.ResponseWriter, r *http.Request, secret string, isProd bool) string {
	// Reuse existing cookie value if present, otherwise mint a new random seed.
	seed := ""
	if c, err := r.Cookie(csrfCookie); err == nil {
		seed = c.Value
	}
	if seed == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		seed = hex.EncodeToString(b)
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookie,
			Value:    seed,
			HttpOnly: false, // must be readable by JS
			Secure:   isProd,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			MaxAge:   int(24 * time.Hour / time.Second),
		})
	}
	return signCSRF(secret, seed)
}

// DoubleCsrfProtection is middleware that enforces the double-submit CSRF pattern.
func DoubleCsrfProtection(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(csrfCookie)
			if err != nil || cookie.Value == "" {
				http.Error(w, `{"error":"CSRF validation failed"}`, http.StatusForbidden)
				return
			}
			token := r.Header.Get(csrfHeader)
			if token == "" {
				token = r.FormValue("_csrf")
			}
			expected := signCSRF(secret, cookie.Value)
			if !hmac.Equal([]byte(token), []byte(expected)) {
				http.Error(w, `{"error":"CSRF validation failed"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func signCSRF(secret, seed string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(seed))
	return hex.EncodeToString(mac.Sum(nil))
}
