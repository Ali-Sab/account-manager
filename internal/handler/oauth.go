package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"account-manager/internal/auth"
	"account-manager/internal/db"
	"account-manager/internal/middleware"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

func sha256Base64URL(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func timingSafeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func getIssuer(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return fmt.Sprintf("%s://%s", proto, host)
}

// DiscoveryCORS adds permissive CORS headers for read-only discovery endpoints
// (/.well-known/*, /jwks.json). It must NOT be applied to /authorize or /token.
func DiscoveryCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ─── Discovery endpoints ──────────────────────────────────────────────────────

// GET /.well-known/oauth-protected-resource[/*]
func (a *App) OAuthProtectedResource(w http.ResponseWriter, r *http.Request) {
	issuer := a.Cfg.JWTIssuer
	suffix := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource")
	if suffix == "" {
		suffix = "/mcp"
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]any{
		"resource":              issuer + suffix,
		"authorization_servers": []string{issuer},
	})
}

// GET /.well-known/oauth-authorization-server
func (a *App) OAuthAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	issuer := a.Cfg.JWTIssuer
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"end_session_endpoint":                  issuer + "/logout",
	})
}

// ─── Authorization endpoint ───────────────────────────────────────────────────

var authorizePageTmpl = template.Must(template.New("auth").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize — Account Manager</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; color: #1a1a1a; }
    h1 { font-size: 1.2rem; margin-bottom: 0.4rem; }
    p  { color: #555; margin: 0 0 1.5rem; font-size: 0.95rem; }
    label { display: block; font-size: 0.85rem; color: #374151; margin-bottom: 4px; }
    input[type=password], input[type=text] { width: 100%; padding: 8px 10px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; margin-bottom: 12px; }
    input:focus { outline: 2px solid #2563eb; border-color: transparent; }
    .actions { display: flex; gap: 10px; margin-top: 4px; }
    button { padding: 9px 22px; border-radius: 6px; border: none; font-size: 0.95rem; cursor: pointer; }
    .allow { background: #2563eb; color: #fff; flex: 1; }
    .allow:hover { background: #1d4ed8; }
    .deny  { background: #f3f4f6; color: #374151; }
    .deny:hover { background: #e5e7eb; }
    .back  { display: block; margin-top: 16px; text-align: center; font-size: 0.85rem; color: #6b7280; text-decoration: none; }
    .back:hover { color: #374151; }
    .error { color: #dc2626; font-size: 0.85rem; margin-bottom: 12px; }
  </style>
</head>
<body>
  <h1>Authorize <strong>{{.ClientName}}</strong></h1>
  <p>This will allow <strong>{{.ClientName}}</strong> to access your account on your behalf.</p>
  {{if .ErrorMsg}}<div class="error">{{.ErrorMsg}}</div>{{end}}
  <form method="POST" action="authorize">
    <input type="hidden" name="client_id"             value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri"          value="{{.RedirectURI}}">
    <input type="hidden" name="code_challenge"        value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    <input type="hidden" name="state"                 value="{{.State}}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" autocomplete="username" required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <label for="totp">2FA code</label>
    <input type="text" id="totp" name="totp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required>
    <input type="hidden" name="_csrf" value="{{.CSRFToken}}">
    <div class="actions">
      <button type="submit" name="decision" value="allow" class="allow">Log in &amp; Allow</button>
      <button type="submit" name="decision" value="deny"  class="deny">Deny</button>
    </div>
  </form>
  <a href="/" class="back">← Back to home</a>
</body>
</html>`))

type authorizePageData struct {
	ClientName          string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	ErrorMsg            string
	CSRFToken           string
}

func renderAuthorizePage(w http.ResponseWriter, data authorizePageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	authorizePageTmpl.Execute(w, data) //nolint:errcheck
}

// authedUserFromCookie returns the username of the user whose refreshToken cookie
// is present and valid, enabling SSO auto-issue on the authorize endpoint.
func (a *App) authedUserFromCookie(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("refreshToken")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	username, valid := db.ValidateRefreshToken(a.DB, cookie.Value)
	return username, valid
}

// GET /authorize
func (a *App) AuthorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if responseType != "code" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}
	client, _ := db.GetOAuthClient(a.DB, clientID)
	if client == nil {
		http.Error(w, "unknown_client", http.StatusBadRequest)
		return
	}
	if !contains(client.RedirectURIs, redirectURI) {
		http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "pkce_required", http.StatusBadRequest)
		return
	}

	if username, ok := a.authedUserFromCookie(r); ok {
		code := randomHex(32)
		expiresAt := time.Now().Add(5 * time.Minute).UnixMilli()
		_ = db.SaveOAuthAuthCode(a.DB, code, clientID, redirectURI, codeChallenge, codeChallengeMethod, expiresAt, username)
		redirect := redirectURI + "?code=" + code
		if state != "" {
			redirect += "&state=" + state
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	clientName := client.Name
	if clientName == "" {
		clientName = clientID
	}
	csrfToken := middleware.GenerateCSRFToken(w, r, a.Cfg.CsrfSecret, a.Cfg.IsProd)
	renderAuthorizePage(w, authorizePageData{
		ClientName:          clientName,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		State:               state,
		CSRFToken:           csrfToken,
	})
}

// POST /authorize
func (a *App) AuthorizePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	state := r.FormValue("state")
	decision := r.FormValue("decision")
	username := r.FormValue("username")
	password := r.FormValue("password")
	totp := r.FormValue("totp")

	client, _ := db.GetOAuthClient(a.DB, clientID)
	if client == nil || !contains(client.RedirectURIs, redirectURI) {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}

	clientName := client.Name
	if clientName == "" {
		clientName = clientID
	}
	pageData := authorizePageData{
		ClientName:          clientName,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		State:               state,
	}

	if decision != "allow" {
		redirect := redirectURI + "?error=access_denied"
		if state != "" {
			redirect += "&state=" + state
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	// Always hash to prevent username-enumeration timing attacks.
	user, _ := db.GetUser(a.DB, username)
	salt := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if user != nil {
		salt = user.Salt
	}
	hash := auth.HashPassword(password, salt)
	if user == nil || hash != user.Hash {
		pageData.ErrorMsg = "Incorrect username or password."
		pageData.CSRFToken = middleware.GenerateCSRFToken(w, r, a.Cfg.CsrfSecret, a.Cfg.IsProd)
		renderAuthorizePage(w, pageData)
		return
	}
	if !auth.VerifyTOTP(user.TotpSecret, totp) {
		pageData.ErrorMsg = "Incorrect 2FA code."
		pageData.CSRFToken = middleware.GenerateCSRFToken(w, r, a.Cfg.CsrfSecret, a.Cfg.IsProd)
		renderAuthorizePage(w, pageData)
		return
	}

	code := randomHex(32)
	expiresAt := time.Now().Add(5 * time.Minute).UnixMilli()
	_ = db.SaveOAuthAuthCode(a.DB, code, clientID, redirectURI, codeChallenge, codeChallengeMethod, expiresAt, user.Username)
	redirect := redirectURI + "?code=" + code
	if state != "" {
		redirect += "&state=" + state
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// ─── Token endpoint ───────────────────────────────────────────────────────────

// GET /token — probe
func (a *App) TokenGET(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]bool{"token_endpoint": true})
}

// POST /token
func (a *App) TokenPOST(w http.ResponseWriter, r *http.Request) {
	params, err := parseTokenBody(r)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid_request")
		return
	}

	clientID, clientSecret := extractClientCreds(r, params)
	client, _ := db.GetOAuthClient(a.DB, clientID)
	w.Header().Set("Cache-Control", "no-store")
	if client == nil {
		jsonErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if !timingSafeEqual(sha256Hex(clientSecret), client.ClientSecretHash) {
		jsonErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	switch params["grant_type"] {
	case "authorization_code":
		a.tokenAuthCode(w, params, client)
	case "refresh_token":
		a.tokenRefresh(w, params, client)
	default:
		jsonErr(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (a *App) tokenAuthCode(w http.ResponseWriter, params map[string]string, client *db.OAuthClient) {
	code := params["code"]
	redirectURI := params["redirect_uri"]
	codeVerifier := params["code_verifier"]
	if code == "" || redirectURI == "" || codeVerifier == "" {
		jsonErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// RFC 7636 §4.1: verifier must be 43–128 unreserved characters.
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		jsonErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	record, _ := db.GetAndConsumeOAuthAuthCode(a.DB, code)
	if record == nil || record.ClientID != client.ClientID || record.ExpiresAt < time.Now().UnixMilli() {
		jsonErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if record.RedirectURI != redirectURI {
		jsonErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if sha256Base64URL(codeVerifier) != record.CodeChallenge {
		jsonErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	a.issueOAuthTokens(w, client, record.Username)
}

func (a *App) tokenRefresh(w http.ResponseWriter, params map[string]string, client *db.OAuthClient) {
	refreshToken := params["refresh_token"]
	if refreshToken == "" {
		jsonErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	record, _ := db.GetAndRotateOAuthRefreshToken(a.DB, sha256Hex(refreshToken))
	if record == nil || record.ClientID != client.ClientID {
		jsonErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	a.issueOAuthTokens(w, client, record.Username)
}

func (a *App) issueOAuthTokens(w http.ResponseWriter, client *db.OAuthClient, username string) {
	isMCP := client.Audience == "mcp"
	var accessExpiry time.Duration
	var accessSeconds int
	if isMCP {
		accessExpiry = 30 * 24 * time.Hour
		accessSeconds = 30 * 24 * 60 * 60
	} else {
		accessExpiry = time.Hour
		accessSeconds = 3600
	}

	accessToken, err := auth.SignToken(a.privateKey(), a.Cfg.JWTIssuer, username, client.Audience, accessExpiry)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "server_error")
		return
	}

	refreshTokenBytes := make([]byte, 32)
	if _, err := cryptoRandRead(refreshTokenBytes); err != nil {
		jsonErr(w, http.StatusInternalServerError, "server_error")
		return
	}
	refreshToken := encodeHex(refreshTokenBytes)
	refreshExpiry := time.Now().Add(365 * 24 * time.Hour).UnixMilli()
	_ = db.SaveOAuthRefreshToken(a.DB, sha256Hex(refreshToken), client.ClientID, refreshExpiry, username)

	jsonOK(w, map[string]any{
		"access_token":  accessToken,
		"token_type":    "bearer",
		"expires_in":    accessSeconds,
		"refresh_token": refreshToken,
	})
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func parseTokenBody(r *http.Request) (map[string]string, error) {
	ct := r.Header.Get("Content-Type")
	params := make(map[string]string)
	if strings.Contains(ct, "application/json") {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		return body, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	for k, v := range r.Form {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}
	return params, nil
}

func extractClientCreds(r *http.Request, params map[string]string) (clientID, clientSecret string) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		if err == nil {
			sep := strings.IndexByte(string(decoded), ':')
			if sep != -1 {
				return string(decoded[:sep]), string(decoded[sep+1:])
			}
		}
	}
	return params["client_id"], params["client_secret"]
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func randomHex(n int) string {
	b := make([]byte, n)
	cryptoRandRead(b) //nolint:errcheck
	return encodeHex(b)
}

