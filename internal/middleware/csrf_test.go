package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateCSRFToken_RoundTrip(t *testing.T) {
	secret := "test-secret"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	token1 := GenerateCSRFToken(w, req, secret, false)
	if token1 == "" {
		t.Fatal("expected non-empty CSRF token")
	}

	// Extract the cookie that was set.
	resp := w.Result()
	var cookieVal string
	for _, c := range resp.Cookies() {
		if c.Name == "csrf_token" {
			cookieVal = c.Value
			break
		}
	}
	if cookieVal == "" {
		t.Fatal("expected csrf_token cookie to be set")
	}

	// Second call with cookie present should return same token.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: cookieVal})
	w2 := httptest.NewRecorder()
	token2 := GenerateCSRFToken(w2, req2, secret, false)
	if token1 != token2 {
		t.Errorf("expected same token when cookie is present: %s vs %s", token1, token2)
	}
}

func TestDoubleCsrfProtection_Valid(t *testing.T) {
	secret := "test-secret"

	// Generate a token.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	token := GenerateCSRFToken(w, req, secret, false)
	cookieVal := w.Result().Cookies()[0].Value

	// Now send a POST with matching cookie + header.
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: cookieVal})
	req2.Header.Set("X-CSRF-Token", token)
	w2 := httptest.NewRecorder()

	called := false
	DoubleCsrfProtection(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(w2, req2)

	if !called {
		t.Error("handler should have been called with valid CSRF token")
	}
	if w2.Code == http.StatusForbidden {
		t.Error("should not get 403 with valid CSRF token")
	}
}

func TestDoubleCsrfProtection_MissingCookie(t *testing.T) {
	secret := "test-secret"
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "whatever")
	w := httptest.NewRecorder()

	DoubleCsrfProtection(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestDoubleCsrfProtection_TamperedToken(t *testing.T) {
	secret := "test-secret"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	GenerateCSRFToken(w, req, secret, false)
	cookieVal := w.Result().Cookies()[0].Value

	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "csrf_token", Value: cookieVal})
	req2.Header.Set("X-CSRF-Token", "tampered-value")
	w2 := httptest.NewRecorder()

	DoubleCsrfProtection(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})).ServeHTTP(w2, req2)

	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w2.Code)
	}
}
