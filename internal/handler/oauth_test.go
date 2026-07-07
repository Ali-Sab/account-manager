package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"account-manager/internal/db"

	"github.com/pquerna/otp/totp"
)

func seedOAuthClient(t *testing.T, app *App) (clientID, clientSecret string) {
	t.Helper()
	clientID = "test-client"
	clientSecret = "supersecret"
	h := sha256.Sum256([]byte(clientSecret))
	hash := hex.EncodeToString(h[:])
	db.UpsertOAuthClient(app.DB, &db.OAuthClient{ //nolint:errcheck
		ClientID:         clientID,
		ClientSecretHash: hash,
		RedirectURIs:     []string{"http://localhost:3000/cb"},
		Name:             "Test App",
		Audience:         "gamebacklog",
	})
	return clientID, clientSecret
}

func TestOAuthAuthorizationServer(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string]any
	decodeJSON(t, w.Body, &resp)
	for _, field := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if resp[field] == "" || resp[field] == nil {
			t.Errorf("missing field %q in authorization server metadata", field)
		}
	}
}

func TestAuthorizeGET_NoSession_ShowsConsent(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)

	// Build PKCE parameters.
	verifier := "testverifier12345678901234567890123456789012345"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	path := "/authorize?client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("http://localhost:3000/cb") +
		"&response_type=code" +
		"&code_challenge=" + challenge +
		"&code_challenge_method=S256"

	w := doRequest(t, router, http.MethodGet, path, nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (consent page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Authorize") {
		t.Error("expected consent page HTML")
	}
}

func TestAuthorizeGET_WithRefreshCookie_Redirects(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	// Plant a valid refresh token in the DB.
	rt := "validcookie"
	db.SaveRefreshToken(app.DB, rt, time.Now().Add(time.Hour).UnixMilli(), "alice") //nolint:errcheck

	verifier := "testverifier12345678901234567890123456789012345"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	path := "/authorize?client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("http://localhost:3000/cb") +
		"&response_type=code" +
		"&code_challenge=" + challenge +
		"&code_challenge_method=S256"

	w := doRequest(t, router, http.MethodGet, path, nil,
		[]*http.Cookie{{Name: "refreshToken", Value: rt}}, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if !strings.Contains(location, "code=") {
		t.Errorf("expected code in redirect, got %s", location)
	}
}

func TestTokenEndpoint_AuthCodeGrant(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	// Plant an auth code.
	verifier := "testverifier12345678901234567890123456789012345"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := "authcode123"
	db.SaveOAuthAuthCode(app.DB, code, clientID, "http://localhost:3000/cb", challenge, "S256", time.Now().Add(5*time.Minute).UnixMilli(), "alice") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "http://localhost:3000/cb",
			"code_verifier": verifier,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("token: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.AccessToken == "" {
		t.Error("expected access_token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected refresh_token")
	}
}

func TestTokenEndpoint_ReplayCode(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	verifier := "testverifier12345678901234567890123456789012345"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := "replaycode"
	db.SaveOAuthAuthCode(app.DB, code, clientID, "http://localhost:3000/cb", challenge, "S256", time.Now().Add(5*time.Minute).UnixMilli(), "alice") //nolint:errcheck

	body := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  "http://localhost:3000/cb",
		"code_verifier": verifier,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}
	// First use succeeds.
	w1 := doRequest(t, router, http.MethodPost, "/token", jsonBody(t, body), nil, nil)
	if w1.Code != http.StatusOK {
		t.Fatalf("first token: want 200, got %d", w1.Code)
	}
	// Second use is rejected.
	w2 := doRequest(t, router, http.MethodPost, "/token", jsonBody(t, body), nil, nil)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("replay: want 400, got %d", w2.Code)
	}
}

func TestTokenEndpoint_WrongClientSecret(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "authorization_code",
			"code":          "x",
			"redirect_uri":  "http://localhost:3000/cb",
			"code_verifier": "x",
			"client_id":     clientID,
			"client_secret": "wrongsecret",
		}), nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestTokenEndpoint_RefreshTokenGrant(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	// Plant a refresh token.
	rt := "plainrefreshtoken"
	h := sha256.Sum256([]byte(rt))
	rtHash := hex.EncodeToString(h[:])
	db.SaveOAuthRefreshToken(app.DB, rtHash, clientID, time.Now().Add(365*24*time.Hour).UnixMilli(), "alice") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": rt,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh grant: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Replay should fail (rotated).
	w2 := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": rt,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("refresh token replay: want 400, got %d", w2.Code)
	}
}

func TestJWKS(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/.well-known/jwks.json", nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Keys []map[string]any `json:"keys"`
	}
	decodeJSON(t, w.Body, &resp)
	if len(resp.Keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
	k := resp.Keys[0]
	if k["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %v", k["kty"])
	}
}

// ─── AuthorizePOST ────────────────────────────────────────────────────────────

// buildPKCE returns a (verifier, challenge) pair long enough to pass RFC 7636.
func buildPKCE() (verifier, challenge string) {
	verifier = "testverifier12345678901234567890123456789012345"
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func TestAuthorizePOST_ValidCredentials(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	username, password, totpSecret := seedAccount(t, app.DB)
	verifier, challenge := buildPKCE()

	code, _ := generateTOTP(totpSecret)
	w := doFormRequest(t, router, http.MethodPost, "/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:3000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"mystate"},
		"decision":              {"allow"},
		"username":              {username},
		"password":              {password},
		"totp":                  {code},
	}, nil, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "code=") {
		t.Errorf("expected code in redirect location, got %s", loc)
	}
	if !strings.Contains(loc, "state=mystate") {
		t.Errorf("expected state in redirect location, got %s", loc)
	}
	_ = verifier
}

func TestAuthorizePOST_WrongPassword(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	username, _, _ := seedAccount(t, app.DB)
	_, challenge := buildPKCE()

	w := doFormRequest(t, router, http.MethodPost, "/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:3000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"decision":              {"allow"},
		"username":              {username},
		"password":              {"wrongpass"},
		"totp":                  {"000000"},
	}, nil, nil)
	// Re-renders consent page with error — not a redirect.
	if w.Code != http.StatusOK {
		t.Errorf("want 200 (re-render), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Incorrect") {
		t.Error("expected error message in re-rendered form")
	}
}

func TestAuthorizePOST_WrongTOTP(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	username, password, _ := seedAccount(t, app.DB)
	_, challenge := buildPKCE()

	w := doFormRequest(t, router, http.MethodPost, "/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:3000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"decision":              {"allow"},
		"username":              {username},
		"password":              {password},
		"totp":                  {"000000"},
	}, nil, nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 (re-render), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "2FA") {
		t.Error("expected 2FA error message in re-rendered form")
	}
}

func TestAuthorizePOST_DenyDecision(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	_, challenge := buildPKCE()

	w := doFormRequest(t, router, http.MethodPost, "/authorize", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:3000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
		"decision":              {"deny"},
	}, nil, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302 on deny, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Errorf("expected access_denied in redirect, got %s", loc)
	}
}

func TestAuthorizePOST_UnknownClient(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	_, challenge := buildPKCE()

	w := doFormRequest(t, router, http.MethodPost, "/authorize", url.Values{
		"client_id":             {"nosuchclient"},
		"redirect_uri":          {"http://localhost:3000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"decision":              {"allow"},
	}, nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for unknown client, got %d", w.Code)
	}
}

// ─── Token edge cases ─────────────────────────────────────────────────────────

func TestTokenEndpoint_ExpiredCode(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	verifier, challenge := buildPKCE()
	code := "expiredcode"
	db.SaveOAuthAuthCode(app.DB, code, clientID, "http://localhost:3000/cb", challenge, "S256",
		time.Now().Add(-time.Minute).UnixMilli(), "alice") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "http://localhost:3000/cb",
			"code_verifier": verifier,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for expired code, got %d", w.Code)
	}
}

func TestTokenEndpoint_RedirectURIMismatch(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	verifier, challenge := buildPKCE()
	code := "mismatchcode"
	db.SaveOAuthAuthCode(app.DB, code, clientID, "http://localhost:3000/cb", challenge, "S256",
		time.Now().Add(5*time.Minute).UnixMilli(), "alice") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "http://attacker.com/steal", // different URI
			"code_verifier": verifier,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for redirect_uri mismatch, got %d", w.Code)
	}
}

func TestTokenEndpoint_PKCEVerifierTooShort(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	shortVerifier := "tooshort"
	h := sha256.Sum256([]byte(shortVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	code := "shortvercode"
	db.SaveOAuthAuthCode(app.DB, code, clientID, "http://localhost:3000/cb", challenge, "S256",
		time.Now().Add(5*time.Minute).UnixMilli(), "alice") //nolint:errcheck

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "http://localhost:3000/cb",
			"code_verifier": shortVerifier, // < 43 chars
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for short PKCE verifier, got %d", w.Code)
	}
}

func TestTokenEndpoint_PKCEVerifierMismatch(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)
	seedAccount(t, app.DB)

	verifier, challenge := buildPKCE()
	code := "mismatchvercode"
	db.SaveOAuthAuthCode(app.DB, code, clientID, "http://localhost:3000/cb", challenge, "S256",
		time.Now().Add(5*time.Minute).UnixMilli(), "alice") //nolint:errcheck

	wrongVerifier := strings.Repeat("x", 43) // right length, wrong value
	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "http://localhost:3000/cb",
			"code_verifier": wrongVerifier,
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for verifier mismatch, got %d", w.Code)
	}
	_ = verifier
}

func TestTokenEndpoint_UnknownGrantType(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "password", // unsupported
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for unknown grant_type, got %d", w.Code)
	}
}

func TestTokenEndpoint_MissingClientSecret(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type": "authorization_code",
			"client_id":  clientID,
			// no client_secret
		}), nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for missing client_secret, got %d", w.Code)
	}
}

// ─── CORS headers ─────────────────────────────────────────────────────────────

func TestDiscoveryCORS_JWKSHasHeaders(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)

	w := doRequest(t, router, http.MethodGet, "/.well-known/jwks.json", nil, nil,
		map[string]string{"Origin": "https://example.com"})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected CORS header on JWKS, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestTokenEndpoint_NoCORSHeaders(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, clientSecret := seedOAuthClient(t, app)

	w := doRequest(t, router, http.MethodPost, "/token",
		jsonBody(t, map[string]string{
			"grant_type":    "authorization_code",
			"client_id":     clientID,
			"client_secret": clientSecret,
		}), nil, map[string]string{"Origin": "https://attacker.com"})
	// No CORS header should be set on /token regardless of response code.
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("token endpoint must not set CORS header, got %q", got)
	}
}

func TestAuthorizeEndpoint_NoCORSHeaders(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	clientID, _ := seedOAuthClient(t, app)
	_, challenge := buildPKCE()

	path := "/authorize?client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("http://localhost:3000/cb") +
		"&response_type=code" +
		"&code_challenge=" + challenge +
		"&code_challenge_method=S256"

	w := doRequest(t, router, http.MethodGet, path, nil, nil,
		map[string]string{"Origin": "https://attacker.com"})
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("authorize endpoint must not set CORS header, got %q", got)
	}
}

// generateTOTP is a local helper so oauth_test.go doesn't need to import totp directly
// (totp is already used via the shared test package; this avoids an unused-import error
// when the function is called from within this file).
func generateTOTP(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
