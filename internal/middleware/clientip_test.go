package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// clientKeyVia sends one request through ClientIP and returns the key that the next handler sees.
func clientKeyVia(t *testing.T, remoteAddr string, headers http.Header) string {
	t.Helper()
	var key string
	calls := 0
	h := ClientIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		key = ClientKey(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for name, values := range headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	if calls != 1 {
		t.Fatalf("next handler: want 1 call, got %d", calls)
	}
	return key
}

func realIPHeader(values ...string) http.Header {
	h := http.Header{}
	for _, v := range values {
		h.Add("X-Real-IP", v)
	}
	return h
}

func TestClientIP_Key(t *testing.T) {
	otherHeaders := http.Header{}
	otherHeaders.Set("True-Client-IP", "203.0.113.50")
	otherHeaders.Set("X-Forwarded-For", "203.0.113.51")

	tests := []struct {
		name    string
		peer    string
		headers http.Header
		want    string
	}{
		{"private peer uses header", "172.18.0.5:4000", realIPHeader("203.0.113.7"), "203.0.113.7"},
		{"loopback peer uses header", "127.0.0.1:4000", realIPHeader("203.0.113.7"), "203.0.113.7"},
		{"IPv6 loopback peer uses header", "[::1]:4000", realIPHeader("203.0.113.7"), "203.0.113.7"},
		{"IPv4-mapped private peer uses header", "[::ffff:172.18.0.5]:4000", realIPHeader("203.0.113.7"), "203.0.113.7"},
		{"public peer ignores header", "198.51.100.1:4000", realIPHeader("203.0.113.7"), "198.51.100.1"},
		{"public IPv6 peer ignores header", "[2001:db8:9:8::1]:4000", realIPHeader("203.0.113.7"), "2001:db8:9:8::/64"},
		{"Tailscale IPv4 peer ignores header", "100.101.102.103:4000", realIPHeader("203.0.113.7"), "100.101.102.103"},
		{"no header", "172.18.0.5:4000", nil, "172.18.0.5"},
		{"header not an address", "172.18.0.5:4000", realIPHeader("not-an-ip"), "172.18.0.5"},
		{"empty header", "172.18.0.5:4000", realIPHeader(""), "172.18.0.5"},
		{"header with spaces", "172.18.0.5:4000", realIPHeader("  203.0.113.7 "), "203.0.113.7"},
		{"last header value wins", "172.18.0.5:4000", realIPHeader("203.0.113.1", "203.0.113.2"), "203.0.113.2"},
		{"other headers not read", "172.18.0.5:4000", otherHeaders, "172.18.0.5"},
		{"IPv6 grouped by /64", "172.18.0.5:4000", realIPHeader("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64"},
		{"IPv6 same /64 same key", "172.18.0.5:4000", realIPHeader("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64"},
		{"IPv6 other /64 other key", "172.18.0.5:4000", realIPHeader("2001:db8:1:3::1"), "2001:db8:1:3::/64"},
		{"Tailscale IPv6 kept whole", "172.18.0.5:4000", realIPHeader("fd7a:115c:a1e0::1234:5678"), "fd7a:115c:a1e0::1234:5678"},
		{"IPv4-mapped header", "172.18.0.5:4000", realIPHeader("::ffff:203.0.113.7"), "203.0.113.7"},
		{"peer without port", "1.2.3.4", nil, "1.2.3.4"},
		{"unreadable peer ignores header", "garbage", realIPHeader("203.0.113.7"), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientKeyVia(t, tt.peer, tt.headers); got != tt.want {
				t.Errorf("want key %q, got %q", tt.want, got)
			}
		})
	}
}

func TestClientKey_WithoutClientIP(t *testing.T) {
	tests := []struct {
		name, peer, want string
	}{
		{"IPv4 peer", "1.2.3.4:1000", "1.2.3.4"},
		{"IPv6 peer", "[2001:db8:1:2:3:4:5:6]:1000", "2001:db8:1:2::/64"},
		{"unreadable peer", "garbage", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.peer
			req.Header.Set("X-Real-IP", "203.0.113.7")
			if got := ClientKey(req); got != tt.want {
				t.Errorf("want key %q, got %q", tt.want, got)
			}
		})
	}
}
