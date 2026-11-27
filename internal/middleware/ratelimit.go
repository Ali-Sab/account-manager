package middleware

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type windowEntry struct {
	count    int
	windowAt time.Time
}

// LimitWindow is the length of every rate-limit window.
const LimitWindow = 15 * time.Minute

// RetryAfterSeconds and TooManyMessage are sent with a refused request.
var (
	RetryAfterSeconds = strconv.Itoa(int(LimitWindow / time.Second))
	TooManyMessage    = fmt.Sprintf("Too many attempts, try again in %d minutes", int(LimitWindow/time.Minute))
)

// tailscaleCGNAT is the IPv4 range that Tailscale assigns device addresses from.
var tailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")

const (
	// defaultMaxKeys bounds memory per limiter. At this size, keys that are not account or local-network keys share overflowKey.
	defaultMaxKeys = 10000
	// fullPruneEvery limits how often a full map is scanned.
	fullPruneEvery = time.Minute
	overflowKey    = "overflow"
)

type RateLimiter struct {
	mu            sync.Mutex
	entries       map[string]*windowEntry
	max           int
	window        time.Duration
	maxKeys       int
	now           func() time.Time
	lastPrune     time.Time
	lastFullPrune time.Time
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*windowEntry),
		max:     max,
		window:  window,
		maxKeys: defaultMaxKeys,
		now:     time.Now,
	}
}

// Middleware counts every request against ClientKey(r).
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl.mu.Lock()
		now := rl.now()
		e := rl.entryLocked(rl.resolveLocked(ClientKey(r), now), now)
		e.count++
		over := e.count > rl.max
		rl.mu.Unlock()
		if over {
			writeTooMany(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Reserve takes one attempt slot for key before a credential check, under one
// lock. ok=false means no slot is left in the current window; release is then
// a no-op. Call release only when the credential was correct, so only failed
// attempts stay counted. release is idempotent and safe for concurrent use. It
// gives back one count in the window the slot was taken in; after that window
// resets or its entry is pruned, release does nothing. A nil limiter returns a
// no-op release and true.
func (rl *RateLimiter) Reserve(key string) (release func(), ok bool) {
	if rl == nil {
		return func() {}, true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	k := rl.resolveLocked(key, now)
	e := rl.entryLocked(k, now)
	if e.count >= rl.max {
		return func() {}, false
	}
	e.count++
	done := false
	return func() {
		rl.mu.Lock()
		defer rl.mu.Unlock()
		if done {
			return
		}
		done = true
		// Give the slot back only in the window it was taken in.
		if rl.entries[k] == e && e.count > 0 {
			e.count--
		}
	}, true
}

func (rl *RateLimiter) expired(e *windowEntry, now time.Time) bool {
	return now.After(e.windowAt.Add(rl.window))
}

func (rl *RateLimiter) pruneLocked(now time.Time) {
	for k, e := range rl.entries {
		if rl.expired(e, now) {
			delete(rl.entries, k)
		}
	}
	rl.lastPrune = now
}

// resolveLocked maps key to the bucket that counts it. Keys outside exemptKey
// share overflowKey once the map is full, so memory stays bounded under a flood.
func (rl *RateLimiter) resolveLocked(key string, now time.Time) string {
	if now.Sub(rl.lastPrune) >= rl.window {
		rl.pruneLocked(now)
	}
	if _, ok := rl.entries[key]; ok {
		return key
	}
	if len(rl.entries) >= rl.maxKeys {
		if now.Sub(rl.lastFullPrune) >= fullPruneEvery {
			rl.pruneLocked(now)
			rl.lastFullPrune = now
		}
		if len(rl.entries) >= rl.maxKeys && !exemptKey(key) {
			return overflowKey
		}
	}
	return key
}

// entryLocked returns the live entry for k, starting a new window when needed.
func (rl *RateLimiter) entryLocked(k string, now time.Time) *windowEntry {
	e, ok := rl.entries[k]
	if !ok || rl.expired(e, now) {
		e = &windowEntry{windowAt: now}
		rl.entries[k] = e
	}
	return e
}

// exemptKey keeps account and local-network keys out of the overflow bucket.
// Their number is bounded by the account count and by the local and Tailscale networks.
func exemptKey(key string) bool {
	if strings.HasPrefix(key, "user:") {
		return true
	}
	ip, err := netip.ParseAddr(key)
	return err == nil && (isLocalAddr(ip) || tailscaleCGNAT.Contains(ip))
}

func writeTooMany(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", RetryAfterSeconds)
	http.Error(w, fmt.Sprintf(`{"error":"%s"}`, TooManyMessage), http.StatusTooManyRequests)
}
