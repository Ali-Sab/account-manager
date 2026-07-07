package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newCountHandler() (http.Handler, *int) {
	count := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusOK)
	})
	return h, &count
}

func makeRequest(rl *RateLimiter, h http.Handler, remoteAddr, xff string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	rl.Middleware(h).ServeHTTP(w, req)
	return w.Code
}

func TestRateLimiter_AllowsUpToMax(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	h, _ := newCountHandler()

	for i := 0; i < 3; i++ {
		code := makeRequest(rl, h, "1.2.3.4:1000", "")
		if code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i+1, code)
		}
	}
}

func TestRateLimiter_BlocksAfterMax(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	h, _ := newCountHandler()

	for i := 0; i < 3; i++ {
		makeRequest(rl, h, "1.2.3.4:1000", "")
	}
	code := makeRequest(rl, h, "1.2.3.4:1000", "")
	if code != http.StatusTooManyRequests {
		t.Errorf("4th request: want 429, got %d", code)
	}
}

func TestRateLimiter_DifferentClientsAreIsolated(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	h, _ := newCountHandler()

	// First client hits its limit.
	makeRequest(rl, h, "1.1.1.1:1000", "")
	code := makeRequest(rl, h, "1.1.1.1:1000", "")
	if code != http.StatusTooManyRequests {
		t.Fatalf("client A 2nd request: want 429, got %d", code)
	}

	// Second client from a different IP should still be allowed.
	code2 := makeRequest(rl, h, "2.2.2.2:1000", "")
	if code2 != http.StatusOK {
		t.Errorf("client B first request: want 200, got %d", code2)
	}
}

func TestRateLimiter_UsesRemoteAddrNotXFF(t *testing.T) {
	// With max=1, a client at RemoteAddr "1.2.3.4" exhausts its bucket.
	// Setting X-Forwarded-For to a different IP must NOT create a new bucket —
	// the second request from the same RemoteAddr must be blocked.
	rl := NewRateLimiter(1, time.Minute)
	h, _ := newCountHandler()

	makeRequest(rl, h, "1.2.3.4:1000", "")

	// Same RemoteAddr, spoofed XFF claiming to be a different client.
	code := makeRequest(rl, h, "1.2.3.4:1000", "9.9.9.9")
	if code != http.StatusTooManyRequests {
		t.Errorf("spoofed XFF must not bypass rate limit: want 429, got %d", code)
	}
}

func TestRateLimiter_WindowResetAllowsNewRequests(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond)
	h, _ := newCountHandler()

	makeRequest(rl, h, "1.2.3.4:1000", "")
	code := makeRequest(rl, h, "1.2.3.4:1000", "")
	if code != http.StatusTooManyRequests {
		t.Fatalf("should be rate-limited before window resets, got %d", code)
	}

	time.Sleep(60 * time.Millisecond)

	code2 := makeRequest(rl, h, "1.2.3.4:1000", "")
	if code2 != http.StatusOK {
		t.Errorf("after window reset: want 200, got %d", code2)
	}
}
