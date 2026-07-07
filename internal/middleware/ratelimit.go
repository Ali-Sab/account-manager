package middleware

import (
	"net/http"
	"sync"
	"time"
)

type windowEntry struct {
	count    int
	windowAt time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*windowEntry
	max     int
	window  time.Duration
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*windowEntry),
		max:     max,
		window:  window,
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		rl.mu.Lock()
		e, ok := rl.entries[ip]
		now := time.Now()
		if !ok || now.After(e.windowAt.Add(rl.window)) {
			e = &windowEntry{count: 0, windowAt: now}
			rl.entries[ip] = e
		}
		e.count++
		over := e.count > rl.max
		rl.mu.Unlock()
		if over {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "900")
			http.Error(w, `{"error":"Too many attempts, try again in 15 minutes"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func realIP(r *http.Request) string {
	// chi's RealIP middleware (applied globally) has already rewritten
	// r.RemoteAddr from X-Forwarded-For / X-Real-IP. Re-reading those
	// headers here would let attackers bypass rate limiting by spoofing them.
	return r.RemoteAddr
}
