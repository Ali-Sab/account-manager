package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"account-manager/internal/config"
	"account-manager/internal/db"
	"account-manager/internal/handler"
	"account-manager/internal/keys"
)

// Generated once: RSA key generation is slow, and every test can use the same key.
var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

func newTestRouterApp(t *testing.T, max int) (*handler.App, http.Handler) {
	t.Helper()
	var keyErr error
	testKeyOnce.Do(func() {
		testKey, keyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if keyErr != nil || testKey == nil {
		t.Fatalf("generate RSA key: %v", keyErr)
	}
	sqlDB, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	cfg := &config.Config{
		JWTIssuer:      "http://localhost:3001",
		CsrfSecret:     "test",
		WebAuthnRPID:   "localhost",
		WebAuthnRPName: "Test",
		RateLimitMax:   max,
	}
	app := &handler.App{DB: sqlDB, Keys: &keys.KeyPair{Private: testKey, Public: &testKey.PublicKey}, Cfg: cfg}
	return app, newRouter(app, cfg)
}

func send(router http.Handler, method, path, body, peer string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = peer
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

const proxyPeer = "172.18.0.5:40000"

// login sends a body that is rejected before any password hashing.
func login(router http.Handler, peer string, headers map[string]string) int {
	return send(router, http.MethodPost, "/api/auth/login", "not-json", peer, headers).Code
}

func from(ip string) map[string]string { return map[string]string{"X-Real-IP": ip} }

func wantCodes(t *testing.T, step string, got []int, want ...int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: want %v, got %v", step, want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: want %v, got %v", step, want, got)
		}
	}
}

func TestRouter_SignInKeyFromXRealIP(t *testing.T) {
	_, router := newTestRouterApp(t, 2)

	var got []int
	for i := 0; i < 3; i++ {
		got = append(got, login(router, proxyPeer, from("203.0.113.7")))
	}
	wantCodes(t, "one client", got, 400, 400, 429)
	wantCodes(t, "second client", []int{login(router, proxyPeer, from("203.0.113.8"))}, 400)
}

func TestRouter_SignInIgnoresOtherHeaders(t *testing.T) {
	_, router := newTestRouterApp(t, 2)

	var got []int
	for i := 1; i <= 3; i++ {
		ip := "203.0.113." + strconv.Itoa(100+i)
		got = append(got, login(router, proxyPeer, map[string]string{
			"X-Real-IP":       "203.0.113.7",
			"True-Client-IP":  ip,
			"X-Forwarded-For": ip,
		}))
	}
	wantCodes(t, "one client", got, 400, 400, 429)
}

func TestRouter_PublicPeerHeaderIgnored(t *testing.T) {
	_, router := newTestRouterApp(t, 2)

	var got []int
	for i := 1; i <= 3; i++ {
		got = append(got, login(router, "198.51.100.1:5000", from("203.0.113."+strconv.Itoa(i))))
	}
	wantCodes(t, "public peer", got, 400, 400, 429)
}

func TestRouter_SignInRoutesShareOneBudget(t *testing.T) {
	_, router := newTestRouterApp(t, 2)
	client := from("203.0.113.7")
	login(router, proxyPeer, client)
	login(router, proxyPeer, client)

	routes := []struct{ method, path string }{
		{http.MethodPost, "/authorize"},
		{http.MethodPost, "/oauth/authorize"},
		{http.MethodPost, "/api/auth/login"},
		{http.MethodPost, "/api/auth/mfa"},
		{http.MethodPost, "/api/auth/recovery"},
		{http.MethodGet, "/api/auth/email/verify"},
		{http.MethodPost, "/api/auth/forgot-password"},
		{http.MethodPost, "/api/auth/reset-password"},
		{http.MethodPost, "/api/webauthn/register/start"},
		{http.MethodPost, "/api/webauthn/register/finish"},
		{http.MethodPost, "/api/webauthn/login/start"},
		{http.MethodPost, "/api/webauthn/login/finish"},
	}
	for _, rt := range routes {
		w := send(router, rt.method, rt.path, "not-json", proxyPeer, client)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("%s %s: want 429, got %d", rt.method, rt.path, w.Code)
		}
	}
}

func seedRouterClient(t *testing.T, app *handler.App) {
	t.Helper()
	sum := sha256.Sum256([]byte("gb-secret"))
	if err := db.UpsertOAuthClient(app.DB, &db.OAuthClient{
		ClientID:         "gamebacklog-web",
		ClientSecretHash: hex.EncodeToString(sum[:]),
		ClientSecret:     "gb-secret",
		RedirectURIs:     []string{"http://localhost:3000/cb"},
		Audience:         "gamebacklog-web",
	}); err != nil {
		t.Fatalf("UpsertOAuthClient: %v", err)
	}
}

// token sends a grant type that does not exist, so an authenticated client gets 400.
func token(router http.Handler, path, secret, clientIP string) int {
	body := url.Values{"grant_type": {"bogus"}, "client_id": {"gamebacklog-web"}, "client_secret": {secret}}.Encode()
	headers := from(clientIP)
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	return send(router, http.MethodPost, path, body, proxyPeer, headers).Code
}

func TestRouter_TokenAuthenticatedNotLimited(t *testing.T) {
	app, router := newTestRouterApp(t, 2)
	seedRouterClient(t, app)

	for _, path := range []string{"/token", "/oauth/token"} {
		var got []int
		for i := 0; i < 5; i++ {
			got = append(got, token(router, path, "gb-secret", "203.0.113.7"))
		}
		wantCodes(t, path, got, 400, 400, 400, 400, 400)
	}
}

func TestRouter_TokenFailedClientAuthLimited(t *testing.T) {
	app, router := newTestRouterApp(t, 2)
	seedRouterClient(t, app)

	wantCodes(t, "wrong secrets", []int{
		token(router, "/token", "nope", "203.0.113.7"),
		token(router, "/oauth/token", "nope", "203.0.113.7"),
	}, 401, 401)
	wantCodes(t, "valid while blocked", []int{
		token(router, "/token", "gb-secret", "203.0.113.7"),
		token(router, "/oauth/token", "gb-secret", "203.0.113.7"),
	}, 429, 429)
	wantCodes(t, "second client", []int{token(router, "/token", "gb-secret", "203.0.113.8")}, 400)
}

func TestRouter_RefreshHasOwnBudget(t *testing.T) {
	_, router := newTestRouterApp(t, 2)
	client := from("203.0.113.7")
	wantCodes(t, "sign-in", []int{
		login(router, proxyPeer, client),
		login(router, proxyPeer, client),
		login(router, proxyPeer, client),
	}, 400, 400, 429)

	refresh := func() int {
		return send(router, http.MethodPost, "/api/auth/refresh", "", proxyPeer, client).Code
	}
	// No CSRF cookie, so an accepted request gets 403.
	wantCodes(t, "refresh", []int{refresh(), refresh(), refresh()}, 403, 403, 429)
}

func TestRouter_SetupHasOwnBudget(t *testing.T) {
	_, router := newTestRouterApp(t, 2)
	client := from("203.0.113.7")
	for i := 0; i < 3; i++ {
		login(router, proxyPeer, client)
		send(router, http.MethodPost, "/api/auth/refresh", "", proxyPeer, client)
	}

	invite := func() int {
		return send(router, http.MethodPost, "/api/invite/accept", "not-json", proxyPeer, client).Code
	}
	wantCodes(t, "setup routes", []int{invite(), invite(), invite()}, 400, 400, 429)
}

func TestRouter_SetsHandlerLimits(t *testing.T) {
	app, _ := newTestRouterApp(t, 4)

	if app.Limits == nil || app.Limits.ClientAuthFailures == nil || app.Limits.SecondFactorFailures == nil {
		t.Fatalf("want both handler limits set, got %+v", app.Limits)
	}
	accepted := func(reserve func(string) (func(), bool), key string) int {
		n := 0
		for i := 0; i < 10; i++ {
			if _, ok := reserve(key); ok {
				n++
			}
		}
		return n
	}
	if n := accepted(app.Limits.ClientAuthFailures.Reserve, "203.0.113.7"); n != 4 {
		t.Errorf("client authentication budget: want 4, got %d", n)
	}
	if n := accepted(app.Limits.SecondFactorFailures.Reserve, "user:alice"); n != 2 {
		t.Errorf("account budget: want 2, got %d", n)
	}
}

func TestRouter_EachCallMakesNewLimiters(t *testing.T) {
	app, router := newTestRouterApp(t, 1)
	client := from("203.0.113.7")
	wantCodes(t, "first router", []int{login(router, proxyPeer, client), login(router, proxyPeer, client)}, 400, 429)
	first := app.Limits

	second := newRouter(app, app.Cfg)
	wantCodes(t, "second router", []int{login(second, proxyPeer, client)}, 400)
	if app.Limits == first {
		t.Error("want new handler limits from the second call")
	}
}

func TestSecondFactorMax(t *testing.T) {
	for in, want := range map[int]int{20: 10, 1: 1, 0: 1, 1000: 500} {
		if got := secondFactorMax(in); got != want {
			t.Errorf("secondFactorMax(%d): want %d, got %d", in, want, got)
		}
	}
}
