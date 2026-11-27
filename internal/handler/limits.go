package handler

import (
	"net/http"

	"account-manager/internal/middleware"
)

// Limits holds the counters that handlers take before they check a credential.
// A nil *Limits, or a nil field, turns the related check off.
type Limits struct {
	// ClientAuthFailures counts failed OAuth client authentications per client address.
	ClientAuthFailures *middleware.RateLimiter
	// SecondFactorFailures counts wrong TOTP, recovery and reset codes per account.
	SecondFactorFailures *middleware.RateLimiter
}

func (a *App) reserveClientAuth(r *http.Request) (release func(), ok bool) {
	if a.Limits == nil {
		return func() {}, true
	}
	return a.Limits.ClientAuthFailures.Reserve(middleware.ClientKey(r))
}

func (a *App) reserveSecondFactor(username string) (release func(), ok bool) {
	if a.Limits == nil {
		return func() {}, true
	}
	return a.Limits.SecondFactorFailures.Reserve("user:" + username)
}

func tooManyAttempts(w http.ResponseWriter) {
	w.Header().Set("Retry-After", middleware.RetryAfterSeconds)
	jsonErr(w, http.StatusTooManyRequests, middleware.TooManyMessage)
}
