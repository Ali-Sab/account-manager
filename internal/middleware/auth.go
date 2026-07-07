package middleware

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	"account-manager/internal/auth"
)

type contextKey string

const ClaimsKey contextKey = "claims"

// RequireAuth validates the Bearer RS256 JWT and attaches claims to the request context.
func RequireAuth(pub *rsa.PublicKey, issuer string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			claims, err := auth.VerifyAccess(pub, issuer, strings.TrimPrefix(header, "Bearer "))
			if err != nil {
				http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
