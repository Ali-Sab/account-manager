package middleware

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPKey struct{}

// Each Tailscale device has its own address in this range.
var tailscaleULA = netip.MustParsePrefix("fd7a:115c:a1e0::/48")

// ClientIP stores the client address for ClientKey. It takes the last X-Real-IP
// value when the direct peer is a loopback or private address (the reverse
// proxy or a local service). Otherwise it takes the peer address.
func ClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := peerAddr(r.RemoteAddr)
		if ok && isLocalAddr(ip) {
			if vals := r.Header.Values("X-Real-IP"); len(vals) > 0 {
				if h, err := netip.ParseAddr(strings.TrimSpace(vals[len(vals)-1])); err == nil {
					ip = h.Unmap().WithZone("")
				}
			}
		}
		if ok {
			r = r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip))
		}
		next.ServeHTTP(w, r)
	})
}

// ClientKey returns the rate-limit key for r: the address that ClientIP stored,
// or the peer address when ClientIP did not run, or "unknown". IPv6 addresses
// outside the Tailscale range are grouped by /64, so one network is one client.
func ClientKey(r *http.Request) string {
	ip, ok := r.Context().Value(clientIPKey{}).(netip.Addr)
	if !ok || !ip.IsValid() {
		ip, ok = peerAddr(r.RemoteAddr)
		if !ok {
			return "unknown"
		}
	}
	return addrKey(ip)
}

func isLocalAddr(ip netip.Addr) bool { return ip.IsLoopback() || ip.IsPrivate() }

func peerAddr(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap().WithZone(""), true
}

func addrKey(ip netip.Addr) string {
	if ip.Is4() || tailscaleULA.Contains(ip) {
		return ip.String()
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return ip.String()
	}
	return p.String()
}
