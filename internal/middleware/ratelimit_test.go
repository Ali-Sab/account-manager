package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

// newTestLimiter returns a limiter with a clock that the test controls.
func newTestLimiter(max int, window time.Duration) (*RateLimiter, *time.Time) {
	rl := NewRateLimiter(max, window)
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rl.now = func() time.Time { return clock }
	return rl, &clock
}

// mustReserve fails the test unless a slot for key is available.
func mustReserve(t *testing.T, rl *RateLimiter, key string) func() {
	t.Helper()
	release, ok := rl.Reserve(key)
	if !ok {
		t.Fatalf("Reserve(%q): want ok, got refused", key)
	}
	if release == nil {
		t.Fatalf("Reserve(%q): release is nil", key)
	}
	return release
}

// mustRefuse fails the test unless Reserve refuses key. It returns the release function.
func mustRefuse(t *testing.T, rl *RateLimiter, key string) func() {
	t.Helper()
	release, ok := rl.Reserve(key)
	if ok {
		t.Fatalf("Reserve(%q): want refused, got ok", key)
	}
	if release == nil {
		t.Fatalf("Reserve(%q): release is nil", key)
	}
	return release
}

func assertEntries(t *testing.T, rl *RateLimiter, want ...string) {
	t.Helper()
	if len(rl.entries) != len(want) {
		t.Errorf("entries: want %d, got %d", len(want), len(rl.entries))
	}
	for _, k := range want {
		if _, ok := rl.entries[k]; !ok {
			t.Errorf("entries: want key %q", k)
		}
	}
}

func TestRateLimiter_KeyIgnoresPort(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	h, _ := newCountHandler()

	if code := makeRequest(rl, h, "1.2.3.4:1000", ""); code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", code)
	}
	if code := makeRequest(rl, h, "1.2.3.4:2000", ""); code != http.StatusTooManyRequests {
		t.Errorf("second request, other port: want 429, got %d", code)
	}
}

func TestRateLimiter_ReserveUpToMax(t *testing.T) {
	rl, _ := newTestLimiter(2, time.Minute)

	mustReserve(t, rl, "k")
	mustReserve(t, rl, "k")
	mustRefuse(t, rl, "k")
	mustReserve(t, rl, "other")
}

func TestRateLimiter_ZeroMaxRefusesAll(t *testing.T) {
	rl, _ := newTestLimiter(0, time.Minute)

	mustRefuse(t, rl, "k")
}

func TestRateLimiter_ReleaseGivesSlotBack(t *testing.T) {
	rl, _ := newTestLimiter(1, time.Minute)

	release := mustReserve(t, rl, "k")
	release()
	mustReserve(t, rl, "k")
}

func TestRateLimiter_ReleaseIdempotent(t *testing.T) {
	rl, _ := newTestLimiter(2, time.Minute)

	r1 := mustReserve(t, rl, "k")
	mustReserve(t, rl, "k")
	r1()
	r1()
	mustReserve(t, rl, "k")
	mustRefuse(t, rl, "k")
}

func TestRateLimiter_ReleaseIdempotentConcurrent(t *testing.T) {
	rl, _ := newTestLimiter(2, time.Minute)
	r1 := mustReserve(t, rl, "k")
	mustReserve(t, rl, "k")

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r1()
		}()
	}
	close(start)
	wg.Wait()

	mustReserve(t, rl, "k")
	mustRefuse(t, rl, "k")
}

func TestRateLimiter_RefusedReleaseIsNoop(t *testing.T) {
	rl, _ := newTestLimiter(1, time.Minute)

	mustReserve(t, rl, "k")
	refused := mustRefuse(t, rl, "k")
	refused()
	mustRefuse(t, rl, "k")
}

func TestRateLimiter_RefusedReservationNotCounted(t *testing.T) {
	rl, _ := newTestLimiter(2, time.Minute)

	r1 := mustReserve(t, rl, "k")
	mustReserve(t, rl, "k")
	for i := 0; i < 5; i++ {
		mustRefuse(t, rl, "k")
	}
	r1()
	mustReserve(t, rl, "k")
	mustRefuse(t, rl, "k")
}

func TestRateLimiter_ReleaseAfterWindowResetIsNoop(t *testing.T) {
	rl, clock := newTestLimiter(1, time.Minute)

	r1 := mustReserve(t, rl, "k")
	*clock = clock.Add(time.Minute + time.Nanosecond)
	mustReserve(t, rl, "k")
	r1()
	mustRefuse(t, rl, "k")
}

func TestRateLimiter_ReleaseKeepsWindowStart(t *testing.T) {
	rl, clock := newTestLimiter(1, time.Minute)

	r1 := mustReserve(t, rl, "k")
	*clock = clock.Add(40 * time.Second)
	r1()
	mustReserve(t, rl, "k")
	*clock = clock.Add(20*time.Second + time.Nanosecond)
	mustReserve(t, rl, "k")
}

func TestRateLimiter_ReleaseAfterPruneIsNoop(t *testing.T) {
	rl, clock := newTestLimiter(1, time.Minute)

	r1 := mustReserve(t, rl, "a")
	*clock = clock.Add(2 * time.Minute)
	mustReserve(t, rl, "b")
	r1()
	assertEntries(t, rl, "b")
	mustRefuse(t, rl, "b")
}

func TestRateLimiter_WindowResets(t *testing.T) {
	rl, clock := newTestLimiter(1, time.Minute)

	mustReserve(t, rl, "k")
	mustRefuse(t, rl, "k")
	*clock = clock.Add(time.Minute + time.Nanosecond)
	mustReserve(t, rl, "k")
}

func TestRateLimiter_ReserveConcurrent(t *testing.T) {
	rl, _ := newTestLimiter(5, time.Minute)
	const n = 64
	var oks [n]bool
	var releases [n]func()

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			releases[i], oks[i] = rl.Reserve("k")
		}(i)
	}
	close(start)
	wg.Wait()

	var taken []func()
	for i := 0; i < n; i++ {
		if oks[i] {
			taken = append(taken, releases[i])
		}
	}
	if len(taken) != 5 {
		t.Fatalf("want 5 accepted, got %d", len(taken))
	}

	for _, release := range taken {
		wg.Add(1)
		go func(release func()) {
			defer wg.Done()
			release()
		}(release)
	}
	wg.Wait()

	for i := 0; i < 5; i++ {
		mustReserve(t, rl, "k")
	}
	mustRefuse(t, rl, "k")
}

func TestRateLimiter_MiddlewareAndReserveConcurrent(t *testing.T) {
	rl, _ := newTestLimiter(100, time.Minute)
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var accepted atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	// 75 of each, so the total is above max. All Middleware requests and
	// reservations use one key.
	for i := 0; i < 75; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "1.2.3.4:1"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				accepted.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if _, ok := rl.Reserve("1.2.3.4"); ok {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := accepted.Load(); got != 100 {
		t.Errorf("want exactly 100 accepted, got %d", got)
	}
}

func TestRateLimiter_PrunesExpiredEntries(t *testing.T) {
	rl, clock := newTestLimiter(1, time.Minute)

	mustReserve(t, rl, "a")
	mustReserve(t, rl, "b")
	*clock = clock.Add(2 * time.Minute)
	mustReserve(t, rl, "c")
	assertEntries(t, rl, "c")
}

func TestRateLimiter_DefaultMaxKeys(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	if rl.maxKeys != 10000 {
		t.Errorf("maxKeys: want 10000, got %d", rl.maxKeys)
	}
}

// newFullLimiter has two public keys stored and the shared overflow slot used.
func newFullLimiter(t *testing.T) *RateLimiter {
	t.Helper()
	rl, _ := newTestLimiter(1, 10*time.Minute)
	rl.maxKeys = 2
	mustReserve(t, rl, "198.51.100.1")
	mustReserve(t, rl, "198.51.100.2")
	mustReserve(t, rl, "203.0.113.1")
	return rl
}

func TestRateLimiter_OverflowWhenFull(t *testing.T) {
	rl := newFullLimiter(t)

	mustRefuse(t, rl, "203.0.113.2")
	mustRefuse(t, rl, "2001:db8:1:2::/64")
	mustRefuse(t, rl, "198.51.100.1")
	assertEntries(t, rl, "198.51.100.1", "198.51.100.2", overflowKey)
}

func TestRateLimiter_PrivateAndAccountKeysNeverOverflow(t *testing.T) {
	rl := newFullLimiter(t)

	keys := []string{"172.18.0.1", "127.0.0.1", "::1", "fd7a:115c:a1e0::1", "100.101.102.103", "user:alice"}
	for _, k := range keys {
		mustReserve(t, rl, k)
	}
	assertEntries(t, rl, append(keys, "198.51.100.1", "198.51.100.2", overflowKey)...)
}

func TestRateLimiter_OverflowReleaseGivesSlotBack(t *testing.T) {
	rl, _ := newTestLimiter(1, 10*time.Minute)
	rl.maxKeys = 1
	mustReserve(t, rl, "198.51.100.1")

	release := mustReserve(t, rl, "203.0.113.1")
	mustRefuse(t, rl, "203.0.113.2")
	release()
	mustReserve(t, rl, "203.0.113.2")
}

func TestRateLimiter_MiddlewareOverflowWhenFull(t *testing.T) {
	rl, _ := newTestLimiter(1, 10*time.Minute)
	rl.maxKeys = 1
	h, _ := newCountHandler()

	steps := []struct {
		peer string
		want int
	}{
		{"198.51.100.1:1", http.StatusOK},
		{"203.0.113.1:1", http.StatusOK},
		{"203.0.113.2:1", http.StatusTooManyRequests},
		{"172.18.0.1:1", http.StatusOK},
	}
	for _, s := range steps {
		if code := makeRequest(rl, h, s.peer, ""); code != s.want {
			t.Errorf("%s: want %d, got %d", s.peer, s.want, code)
		}
	}
	assertEntries(t, rl, "198.51.100.1", "172.18.0.1", overflowKey)
}

func TestRateLimiter_FullPruneThrottled(t *testing.T) {
	rl, clock := newTestLimiter(10, 10*time.Minute)
	rl.maxKeys = 2
	t0 := *clock

	mustReserve(t, rl, "a")
	mustReserve(t, rl, "b")

	*clock = t0.Add(5 * time.Minute)
	mustReserve(t, rl, "c")
	assertEntries(t, rl, "a", "b", overflowKey)
	if t.Failed() {
		t.FailNow()
	}

	rl.entries["a"].windowAt = t0.Add(-20 * time.Minute)
	rl.entries["b"].windowAt = t0.Add(-20 * time.Minute)

	*clock = t0.Add(5*time.Minute + 10*time.Second)
	mustReserve(t, rl, "d")
	if _, ok := rl.entries["d"]; ok {
		t.Error("d: want no own entry within fullPruneEvery of the last full prune")
	}

	*clock = t0.Add(6*time.Minute + 10*time.Second)
	mustReserve(t, rl, "e")
	assertEntries(t, rl, overflowKey, "e")
}

func TestRateLimiter_NilLimiter(t *testing.T) {
	var rl *RateLimiter

	release := mustReserve(t, rl, "k")
	release()
	release()
}

func TestRateLimiter_MiddlewareStillReturns429Body(t *testing.T) {
	rl := NewRateLimiter(0, time.Minute)
	h, count := newCountHandler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	rl.Middleware(h).ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "900" {
		t.Errorf("Retry-After: want 900, got %q", got)
	}
	if !strings.Contains(w.Body.String(), "Too many attempts") {
		t.Errorf("unexpected body: %s", w.Body.String())
	}
	if *count != 0 {
		t.Errorf("next handler: want 0 calls, got %d", *count)
	}
}
