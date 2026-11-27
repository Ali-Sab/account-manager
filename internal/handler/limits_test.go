package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"
	"account-manager/internal/middleware"
)

const (
	wrongTOTP     = "abcdef"
	wrongRecovery = "xxxx-xxxx-xx"
	tooManyText   = "Too many attempts"
)

func newLimiter(max int) *middleware.RateLimiter {
	return middleware.NewRateLimiter(max, 15*time.Minute)
}

// newSecondFactorApp returns an app with only the per-account limit on.
func newSecondFactorApp(t *testing.T, max int) *App {
	t.Helper()
	app := newTestApp(t)
	app.Limits = &Limits{SecondFactorFailures: newLimiter(max)}
	return app
}

// newClientAuthApp returns an app with only the client-authentication limit on.
func newClientAuthApp(t *testing.T, max int) *App {
	t.Helper()
	app := newTestApp(t)
	app.Limits = &Limits{ClientAuthFailures: newLimiter(max)}
	return app
}

// useFileDB replaces the in-memory database, because each ":memory:" connection
// is its own empty database.
func useFileDB(t *testing.T, app *App) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "am.db"))
	if err != nil {
		t.Fatalf("open file DB: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	app.DB = d
}

func newTOTPSecret(t *testing.T) string {
	t.Helper()
	secret, err := auth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	return secret
}

func validTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := generateTOTP(secret)
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	return code
}

func mfaTokenFor(t *testing.T, app *App, username string) string {
	t.Helper()
	tok, err := auth.SignMFAToken(app.privateKey(), app.Cfg.JWTIssuer, username)
	if err != nil {
		t.Fatalf("SignMFAToken: %v", err)
	}
	return tok
}

func postMFA(t *testing.T, app *App, router http.Handler, username, code string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, router, http.MethodPost, "/api/auth/mfa",
		jsonBody(t, map[string]string{"mfaToken": mfaTokenFor(t, app, username), "code": code}), nil, nil)
}

func postRecovery(t *testing.T, app *App, router http.Handler, username, code string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, router, http.MethodPost, "/api/auth/recovery",
		jsonBody(t, map[string]string{"mfaToken": mfaTokenFor(t, app, username), "code": code}), nil, nil)
}

func saveResetToken(t *testing.T, app *App, token, username string) {
	t.Helper()
	if err := db.SavePasswordResetToken(app.DB, token, username, time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatalf("SavePasswordResetToken: %v", err)
	}
}

func postReset(t *testing.T, router http.Handler, token, newPassword, code string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, router, http.MethodPost, "/api/auth/reset-password",
		jsonBody(t, map[string]string{"token": token, "newPassword": newPassword, "totpCode": code}), nil, nil)
}

func postAuthorize(t *testing.T, router http.Handler, clientID, username, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	_, challenge := buildPKCE()
	return doFormRequest(t, router, http.MethodPost, "/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:3000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"decision":              {"allow"},
		"username":              {username},
		"password":              {password},
		"totp":                  {code},
	}, nil, nil)
}

// postToken sends a token request with a grant type that does not exist, so an
// authenticated client gets 400. An empty remoteAddr keeps the default peer.
func postToken(router http.Handler, clientID, secret, remoteAddr string) *httptest.ResponseRecorder {
	vals := url.Values{"grant_type": {"bogus"}, "client_id": {clientID}, "client_secret": {secret}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func wantStatus(t *testing.T, step string, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("%s: want %d, got %d: %s", step, want, w.Code, w.Body.String())
	}
}

func wantTooMany(t *testing.T, step string, w *httptest.ResponseRecorder) {
	t.Helper()
	wantStatus(t, step, w, http.StatusTooManyRequests)
	if got := w.Header().Get("Retry-After"); got != "900" {
		t.Errorf("%s: Retry-After: want 900, got %q", step, got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("%s: Content-Type: want JSON, got %q", step, ct)
	}
	var resp map[string]string
	decodeJSON(t, w.Body, &resp)
	if len(resp) != 1 || resp["error"] != "Too many attempts, try again in 15 minutes" {
		t.Errorf("%s: unexpected body %v", step, resp)
	}
}

// concurrentStatuses runs send n times at once and counts the reply codes.
// Requests are built before the start, so send must not call testing.T.
func concurrentStatuses(n int, send func(i int) int) map[int]int {
	codes := make([]int, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = send(i)
		}(i)
	}
	close(start)
	wg.Wait()
	counts := map[int]int{}
	for _, c := range codes {
		counts[c]++
	}
	return counts
}

func concurrentCodeRequests(t *testing.T, app *App, router http.Handler, n int, path, username, code string) map[int]int {
	t.Helper()
	reqs := make([]*http.Request, n)
	for i := range reqs {
		reqs[i] = httptest.NewRequest(http.MethodPost, path,
			jsonBody(t, map[string]string{"mfaToken": mfaTokenFor(t, app, username), "code": code}))
		reqs[i].Header.Set("Content-Type", "application/json")
	}
	return concurrentStatuses(n, func(i int) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, reqs[i])
		return w.Code
	})
}

// ─── MFA ──────────────────────────────────────────────────────────────────────

func TestLimits_MFA_AccountLimit(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	username, _, secret := seedAccount(t, app.DB)

	wantStatus(t, "wrong 1", postMFA(t, app, router, username, wrongTOTP), http.StatusUnauthorized)
	wantStatus(t, "wrong 2", postMFA(t, app, router, username, wrongTOTP), http.StatusUnauthorized)
	w := postMFA(t, app, router, username, validTOTP(t, secret))
	wantTooMany(t, "valid while blocked", w)
	for _, c := range w.Result().Cookies() {
		if c.Name == "refreshToken" && c.Value != "" {
			t.Error("blocked request must not set a refreshToken cookie")
		}
	}

	// The count follows the account, not the client address.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa",
		jsonBody(t, map[string]string{"mfaToken": mfaTokenFor(t, app, username), "code": validTOTP(t, secret)}))
	req.RemoteAddr = "192.0.2.99:1"
	other := httptest.NewRecorder()
	router.ServeHTTP(other, req)
	wantStatus(t, "other address", other, http.StatusTooManyRequests)
}

func TestLimits_MFA_SuccessNotCounted(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	username, _, secret := seedAccount(t, app.DB)

	for i := 0; i < 3; i++ {
		wantStatus(t, "valid code", postMFA(t, app, router, username, validTOTP(t, secret)), http.StatusOK)
	}
}

func TestLimits_MFA_InvalidTokenNotCounted(t *testing.T) {
	app := newSecondFactorApp(t, 1)
	router := buildRouter(app)
	username, _, secret := seedAccount(t, app.DB)

	for i := 0; i < 3; i++ {
		w := doRequest(t, router, http.MethodPost, "/api/auth/mfa",
			jsonBody(t, map[string]string{"mfaToken": "bad.token.here", "code": wrongTOTP}), nil, nil)
		wantStatus(t, "invalid token", w, http.StatusUnauthorized)
	}
	wantStatus(t, "wrong code", postMFA(t, app, router, username, wrongTOTP), http.StatusUnauthorized)
	wantTooMany(t, "valid while blocked", postMFA(t, app, router, username, validTOTP(t, secret)))
}

func TestLimits_MFA_LimitIsPerAccount(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	alice, _, aliceSecret := seedAccount(t, app.DB)
	bobSecret := newTOTPSecret(t)
	seedUser(t, app.DB, "bob", bobSecret)

	wantStatus(t, "alice wrong 1", postMFA(t, app, router, alice, wrongTOTP), http.StatusUnauthorized)
	wantStatus(t, "alice wrong 2", postMFA(t, app, router, alice, wrongTOTP), http.StatusUnauthorized)
	wantStatus(t, "alice blocked", postMFA(t, app, router, alice, validTOTP(t, aliceSecret)), http.StatusTooManyRequests)
	wantStatus(t, "bob valid", postMFA(t, app, router, "bob", validTOTP(t, bobSecret)), http.StatusOK)
}

func TestLimits_MFA_ConcurrentWrongCodesCapped(t *testing.T) {
	app := newSecondFactorApp(t, 3)
	useFileDB(t, app)
	username, _, secret := seedAccount(t, app.DB)
	router := buildRouter(app)

	counts := concurrentCodeRequests(t, app, router, 20, "/api/auth/mfa", username, wrongTOTP)
	if counts[http.StatusUnauthorized] != 3 || counts[http.StatusTooManyRequests] != 17 {
		t.Fatalf("want 3x401 and 17x429, got %v", counts)
	}
	wantTooMany(t, "valid while blocked", postMFA(t, app, router, username, validTOTP(t, secret)))
}

// ─── Recovery ─────────────────────────────────────────────────────────────────

func TestLimits_Recovery_SharesAccountLimit(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	_, codes := seedUser(t, app.DB, "alice", newTOTPSecret(t))

	wantStatus(t, "wrong MFA 1", postMFA(t, app, router, "alice", wrongTOTP), http.StatusUnauthorized)
	wantStatus(t, "wrong MFA 2", postMFA(t, app, router, "alice", wrongTOTP), http.StatusUnauthorized)
	wantTooMany(t, "valid recovery while blocked", postRecovery(t, app, router, "alice", codes[0]))

	u, err := db.GetUser(app.DB, "alice")
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v %v", u, err)
	}
	if len(u.RecoveryCodes) != len(codes) {
		t.Errorf("blocked request must not use a recovery code: want %d left, got %d", len(codes), len(u.RecoveryCodes))
	}
}

func TestLimits_Recovery_WrongCodesCount(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	username, _, secret := seedAccount(t, app.DB)

	wantStatus(t, "wrong recovery 1", postRecovery(t, app, router, username, wrongRecovery), http.StatusUnauthorized)
	wantStatus(t, "wrong recovery 2", postRecovery(t, app, router, username, wrongRecovery), http.StatusUnauthorized)
	wantTooMany(t, "valid MFA while blocked", postMFA(t, app, router, username, validTOTP(t, secret)))
}

func TestLimits_Recovery_SuccessReleases(t *testing.T) {
	app := newSecondFactorApp(t, 1)
	router := buildRouter(app)
	secret := newTOTPSecret(t)
	_, codes := seedUser(t, app.DB, "alice", secret)

	wantStatus(t, "valid recovery", postRecovery(t, app, router, "alice", codes[0]), http.StatusOK)
	wantStatus(t, "wrong MFA", postMFA(t, app, router, "alice", wrongTOTP), http.StatusUnauthorized)
	wantTooMany(t, "valid MFA while blocked", postMFA(t, app, router, "alice", validTOTP(t, secret)))
}

func TestLimits_Recovery_ConcurrentWrongCodesCapped(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	useFileDB(t, app)
	username, _, _ := seedAccount(t, app.DB)
	router := buildRouter(app)

	counts := concurrentCodeRequests(t, app, router, 6, "/api/auth/recovery", username, wrongRecovery)
	if counts[http.StatusUnauthorized] != 2 || counts[http.StatusTooManyRequests] != 4 {
		t.Fatalf("want 2x401 and 4x429, got %v", counts)
	}
}

// ─── Password reset ───────────────────────────────────────────────────────────

func TestLimits_ResetPassword_AccountLimit(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	username, _, secret := seedAccount(t, app.DB)
	saveResetToken(t, app, "limitresettoken", username)
	before, err := db.GetUser(app.DB, username)
	if err != nil || before == nil {
		t.Fatalf("GetUser: %v %v", before, err)
	}

	wantStatus(t, "wrong 1", postReset(t, router, "limitresettoken", "brandnewpass123", wrongTOTP), http.StatusUnauthorized)
	wantStatus(t, "wrong 2", postReset(t, router, "limitresettoken", "brandnewpass123", wrongTOTP), http.StatusUnauthorized)
	wantTooMany(t, "valid while blocked", postReset(t, router, "limitresettoken", "brandnewpass123", validTOTP(t, secret)))

	after, err := db.GetUser(app.DB, username)
	if err != nil || after == nil {
		t.Fatalf("GetUser: %v %v", after, err)
	}
	if after.Hash != before.Hash {
		t.Error("password hash should be unchanged")
	}
}

func TestLimits_ResetPassword_EarlyRejectionsNotCounted(t *testing.T) {
	app := newSecondFactorApp(t, 1)
	router := buildRouter(app)
	username, _, secret := seedAccount(t, app.DB)
	saveResetToken(t, app, "earlyresettoken", username)

	wantStatus(t, "short password", postReset(t, router, "earlyresettoken", "short", wrongTOTP), http.StatusBadRequest)
	wantStatus(t, "unknown link", postReset(t, router, "nosuchtoken", "brandnewpass123", wrongTOTP), http.StatusUnauthorized)
	w := postReset(t, router, "earlyresettoken", "brandnewpass123", wrongTOTP)
	wantStatus(t, "wrong code", w, http.StatusUnauthorized)
	wantTooMany(t, "valid while blocked", postReset(t, router, "earlyresettoken", "brandnewpass123", validTOTP(t, secret)))
}

func TestLimits_ResetPassword_SuccessReleases(t *testing.T) {
	app := newSecondFactorApp(t, 1)
	router := buildRouter(app)
	username, _, secret := seedAccount(t, app.DB)
	saveResetToken(t, app, "releaseresettoken", username)

	wantStatus(t, "valid reset", postReset(t, router, "releaseresettoken", "brandnewpass123", validTOTP(t, secret)), http.StatusOK)
	wantStatus(t, "valid MFA", postMFA(t, app, router, username, validTOTP(t, secret)), http.StatusOK)
}

// ─── AuthorizePOST ────────────────────────────────────────────────────────────

func TestLimits_AuthorizePOST_AccountLimit(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	username, password, secret := seedAccount(t, app.DB)

	for i := 0; i < 2; i++ {
		w := postAuthorize(t, router, clientID, username, password, wrongTOTP)
		wantStatus(t, "wrong TOTP", w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "Incorrect 2FA code.") {
			t.Fatal("expected 2FA error message")
		}
	}

	w := postAuthorize(t, router, clientID, username, password, validTOTP(t, secret))
	wantStatus(t, "valid while blocked", w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Too many attempts. Try again in 15 minutes.") {
		t.Errorf("expected limit message in the page: %s", w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("want no Location header, got %q", loc)
	}
	var codes int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM oauth_auth_codes").Scan(&codes); err != nil {
		t.Fatalf("count auth codes: %v", err)
	}
	if codes != 0 {
		t.Errorf("want no saved auth code, got %d", codes)
	}
}

func TestLimits_AuthorizePOST_SuccessReleases(t *testing.T) {
	app := newSecondFactorApp(t, 1)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	username, password, secret := seedAccount(t, app.DB)

	for i := 0; i < 2; i++ {
		wantStatus(t, "valid", postAuthorize(t, router, clientID, username, password, validTOTP(t, secret)), http.StatusFound)
	}
	wantStatus(t, "wrong TOTP", postAuthorize(t, router, clientID, username, password, wrongTOTP), http.StatusOK)
	w := postAuthorize(t, router, clientID, username, password, validTOTP(t, secret))
	wantStatus(t, "valid while blocked", w, http.StatusOK)
	if !strings.Contains(w.Body.String(), tooManyText) {
		t.Error("expected limit message in the page")
	}
}

func TestLimits_AuthorizePOST_WrongPasswordNotCounted(t *testing.T) {
	app := newSecondFactorApp(t, 1)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	username, password, secret := seedAccount(t, app.DB)

	for i := 0; i < 2; i++ {
		w := postAuthorize(t, router, clientID, username, "wrongpass", wrongTOTP)
		if !strings.Contains(w.Body.String(), "Incorrect username or password.") {
			t.Fatal("expected password error message")
		}
	}
	w := postAuthorize(t, router, clientID, username, password, wrongTOTP)
	if !strings.Contains(w.Body.String(), "Incorrect 2FA code.") {
		t.Fatalf("expected 2FA error message: %s", w.Body.String())
	}
	w = postAuthorize(t, router, clientID, username, password, validTOTP(t, secret))
	wantStatus(t, "valid while blocked", w, http.StatusOK)
	if !strings.Contains(w.Body.String(), tooManyText) {
		t.Error("expected limit message in the page")
	}
}

func TestLimits_AuthorizePOST_WrongPasswordWhileBlocked(t *testing.T) {
	app := newSecondFactorApp(t, 2)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	username, _, secret := seedAccount(t, app.DB)

	wantStatus(t, "wrong MFA 1", postMFA(t, app, router, username, wrongTOTP), http.StatusUnauthorized)
	wantStatus(t, "wrong MFA 2", postMFA(t, app, router, username, wrongTOTP), http.StatusUnauthorized)
	wantStatus(t, "account is blocked", postMFA(t, app, router, username, validTOTP(t, secret)), http.StatusTooManyRequests)

	w := postAuthorize(t, router, clientID, username, "wrongpass", validTOTP(t, secret))
	wantStatus(t, "wrong password", w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Incorrect username or password.") {
		t.Error("expected password error message")
	}
	if strings.Contains(w.Body.String(), tooManyText) {
		t.Error("a wrong password must not show the limit message")
	}
}

// ─── Client authentication ────────────────────────────────────────────────────

func TestLimits_Token_ClientAuthFailuresLimit(t *testing.T) {
	app := newClientAuthApp(t, 2)
	router := buildRouter(app)
	clientID, secret := seedOAuthClient(t, app)

	wantStatus(t, "wrong 1", postToken(router, clientID, "nope", ""), http.StatusUnauthorized)
	wantStatus(t, "wrong 2", postToken(router, clientID, "nope", ""), http.StatusUnauthorized)
	w := postToken(router, clientID, secret, "")
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control: want no-store, got %q", got)
	}
	wantTooMany(t, "valid while blocked", w)
	wantStatus(t, "other address", postToken(router, clientID, secret, "192.0.2.99:1"), http.StatusBadRequest)
}

func TestLimits_Token_UnknownClientCounted(t *testing.T) {
	app := newClientAuthApp(t, 1)
	router := buildRouter(app)
	clientID, secret := seedOAuthClient(t, app)

	wantStatus(t, "unknown client", postToken(router, "nobody", "x", ""), http.StatusUnauthorized)
	wantTooMany(t, "valid while blocked", postToken(router, clientID, secret, ""))
}

func TestLimits_Token_ParseErrorNotCounted(t *testing.T) {
	app := newClientAuthApp(t, 1)
	router := buildRouter(app)
	clientID, secret := seedOAuthClient(t, app)

	for i := 0; i < 3; i++ {
		w := doRequest(t, router, http.MethodPost, "/token", strings.NewReader("not-json"), nil, nil)
		wantStatus(t, "unreadable body", w, http.StatusBadRequest)
	}
	wantStatus(t, "wrong secret", postToken(router, clientID, "nope", ""), http.StatusUnauthorized)
	wantTooMany(t, "valid while blocked", postToken(router, clientID, secret, ""))
}

func TestLimits_Token_AuthenticatedNotCounted(t *testing.T) {
	app := newClientAuthApp(t, 2)
	router := buildRouter(app)
	clientID, secret := seedOAuthClient(t, app)

	for i := 0; i < 5; i++ {
		wantStatus(t, "valid client, bogus grant", postToken(router, clientID, secret, ""), http.StatusBadRequest)
	}
}

func TestLimits_MCPClientInfo_ClientAuthFailuresLimit(t *testing.T) {
	t.Run("wrong secrets are counted", func(t *testing.T) {
		app := newClientAuthApp(t, 2)
		router := buildRouter(app)
		seedClient(t, app, "gamebacklog-web", "gb-secret", "http://localhost:3000/cb", "")

		wantStatus(t, "wrong 1", postMCPClient(router, "gamebacklog-web", "nope", ""), http.StatusUnauthorized)
		wantStatus(t, "wrong 2", postMCPClient(router, "gamebacklog-web", "nope", ""), http.StatusUnauthorized)
		wantTooMany(t, "valid while blocked", postMCPClient(router, "gamebacklog-web", "gb-secret", ""))
	})

	t.Run("missing Basic auth is not counted", func(t *testing.T) {
		app := newClientAuthApp(t, 2)
		router := buildRouter(app)
		seedClient(t, app, "gamebacklog-web", "gb-secret", "http://localhost:3000/cb", "")

		for i := 0; i < 3; i++ {
			w := doRequest(t, router, http.MethodPost, "/api/mcp-client", nil, nil, nil)
			wantStatus(t, "no credentials", w, http.StatusUnauthorized)
		}
		wantStatus(t, "valid", postMCPClient(router, "gamebacklog-web", "gb-secret", ""), http.StatusOK)
	})
}

func TestLimits_MCPClientInfo_AuthenticatedNotCounted(t *testing.T) {
	app := newClientAuthApp(t, 1)
	router := buildRouter(app)
	seedClient(t, app, "gamebacklog-web", "gb-secret", "http://localhost:3000/cb", "")
	seedClient(t, app, "pi-health", "ph-secret", "http://ph.local/cb", "")

	for i := 0; i < 3; i++ {
		wantStatus(t, "other client", postMCPClient(router, "pi-health", "ph-secret", ""), http.StatusForbidden)
		wantStatus(t, "allowed client", postMCPClient(router, "gamebacklog-web", "gb-secret", ""), http.StatusOK)
	}
	wantStatus(t, "wrong secret", postMCPClient(router, "pi-health", "nope", ""), http.StatusUnauthorized)
	wantTooMany(t, "valid while blocked", postMCPClient(router, "gamebacklog-web", "gb-secret", ""))
}

func TestLimits_ClientAuthSharedByTokenAndMCPClient(t *testing.T) {
	app := newClientAuthApp(t, 2)
	router := buildRouter(app)
	seedClient(t, app, "gamebacklog-web", "gb-secret", "http://localhost:3000/cb", "")

	wantStatus(t, "wrong on /token", postToken(router, "gamebacklog-web", "nope", ""), http.StatusUnauthorized)
	wantStatus(t, "wrong on /api/mcp-client", postMCPClient(router, "gamebacklog-web", "nope", ""), http.StatusUnauthorized)
	wantStatus(t, "/token blocked", postToken(router, "gamebacklog-web", "gb-secret", ""), http.StatusTooManyRequests)
	wantStatus(t, "/api/mcp-client blocked", postMCPClient(router, "gamebacklog-web", "gb-secret", ""), http.StatusTooManyRequests)
}

// ─── Limits off ───────────────────────────────────────────────────────────────

func TestLimits_NilDisablesChecks(t *testing.T) {
	for name, limits := range map[string]*Limits{"nil Limits": nil, "nil fields": {}} {
		t.Run(name, func(t *testing.T) {
			app := newTestApp(t)
			app.Limits = limits
			router := buildRouter(app)
			clientID, _ := seedOAuthClient(t, app)
			username, _, _ := seedAccount(t, app.DB)

			for i := 0; i < 5; i++ {
				wantStatus(t, "wrong client secret", postToken(router, clientID, "nope", ""), http.StatusUnauthorized)
				wantStatus(t, "wrong MFA code", postMFA(t, app, router, username, wrongTOTP), http.StatusUnauthorized)
			}
		})
	}
}
