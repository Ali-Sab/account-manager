package handler

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"account-manager/internal/db"
)

func seedClient(t *testing.T, app *App, id, secret, redirect, backchannel string) {
	t.Helper()
	if err := db.UpsertOAuthClient(app.DB, &db.OAuthClient{
		ClientID:             id,
		ClientSecretHash:     sha256Hex(secret),
		ClientSecret:         secret,
		RedirectURIs:         []string{redirect},
		Audience:             id,
		BackchannelLogoutURI: backchannel,
	}); err != nil {
		t.Fatalf("UpsertOAuthClient %s: %v", id, err)
	}
}

func newMCPTestApp(t *testing.T) (*App, http.Handler) {
	t.Helper()
	app := newTestApp(t)
	seedClient(t, app, "gamebacklog-web", "gb-secret", "http://localhost:3000/cb", "http://gb.local/backchannel")
	seedClient(t, app, "claude-mcp", "mcp-plain", "http://mcp.local/cb", "")
	seedClient(t, app, "pi-health", "ph-secret", "http://ph.local/cb", "http://ph.local/backchannel")
	return app, buildRouter(app)
}

// postMCPClient sends POST /api/mcp-client with Basic auth.
func postMCPClient(router http.Handler, id, secret, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/mcp-client", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(id, secret)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func getClient(t *testing.T, app *App, id string) db.OAuthClient {
	t.Helper()
	c, err := db.GetOAuthClient(app.DB, id)
	if err != nil || c == nil {
		t.Fatalf("GetOAuthClient %s: %v %v", id, c, err)
	}
	return *c
}

func assertMCPCredentials(t *testing.T, w *httptest.ResponseRecorder, wantSecret string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	decodeJSON(t, w.Body, &resp)
	want := map[string]string{"client_id": "claude-mcp", "client_secret": wantSecret}
	if !reflect.DeepEqual(resp, want) {
		t.Errorf("want body %v, got %v", want, resp)
	}
}

func assertRejected(t *testing.T, w *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if w.Code != wantStatus {
		t.Errorf("want %d, got %d: %s", wantStatus, w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, "mcp-plain") || strings.Contains(body, "client_secret") {
		t.Errorf("rejected response must not contain credentials: %s", body)
	}
}

func TestMCPClientInfo_NoCredentials(t *testing.T) {
	_, router := newMCPTestApp(t)

	w := doRequest(t, router, http.MethodPost, "/api/mcp-client", nil, nil, nil)
	assertRejected(t, w, http.StatusUnauthorized)
}

func TestMCPClientInfo_WrongSecret(t *testing.T) {
	_, router := newMCPTestApp(t)

	assertRejected(t, postMCPClient(router, "gamebacklog-web", "nope", ""), http.StatusUnauthorized)
}

func TestMCPClientInfo_UnknownClient(t *testing.T) {
	_, router := newMCPTestApp(t)

	assertRejected(t, postMCPClient(router, "nobody", "x", ""), http.StatusUnauthorized)
}

func TestMCPClientInfo_AllowedClient(t *testing.T) {
	_, router := newMCPTestApp(t)

	assertMCPCredentials(t, postMCPClient(router, "gamebacklog-web", "gb-secret", ""), "mcp-plain")
}

func TestMCPClientInfo_OtherClientForbidden(t *testing.T) {
	_, router := newMCPTestApp(t)

	assertRejected(t, postMCPClient(router, "pi-health", "ph-secret", ""), http.StatusForbidden)
}

func TestMCPClientInfo_MCPClientItselfForbidden(t *testing.T) {
	_, router := newMCPTestApp(t)

	assertRejected(t, postMCPClient(router, "claude-mcp", "mcp-plain", ""), http.StatusForbidden)
}

func TestMCPClientInfo_SimilarClientIDForbidden(t *testing.T) {
	app, router := newMCPTestApp(t)

	for _, id := range []string{"gamebacklog", "gamebacklog-web-2", "Gamebacklog-Web"} {
		seedClient(t, app, id, "similar-secret", "http://similar.local/cb", "")
		t.Run(id, func(t *testing.T) {
			assertRejected(t, postMCPClient(router, id, "similar-secret", ""), http.StatusForbidden)
		})
	}
}

func TestMCPClientInfo_OtherClientWrongSecret(t *testing.T) {
	_, router := newMCPTestApp(t)

	assertRejected(t, postMCPClient(router, "pi-health", "nope", ""), http.StatusUnauthorized)
}

func TestMCPClientInfo_IgnoresBody(t *testing.T) {
	app, router := newMCPTestApp(t)
	before := getClient(t, app, "gamebacklog-web")

	w := postMCPClient(router, "gamebacklog-web", "gb-secret", `{"redirect_uri":"https://other.example/cb"}`)
	assertMCPCredentials(t, w, "mcp-plain")

	after := getClient(t, app, "gamebacklog-web")
	if want := []string{"http://localhost:3000/cb"}; !reflect.DeepEqual(after.RedirectURIs, want) {
		t.Errorf("redirect URIs: want %v, got %v", want, after.RedirectURIs)
	}
	if after.BackchannelLogoutURI != "http://gb.local/backchannel" {
		t.Errorf("backchannel logout URI changed to %q", after.BackchannelLogoutURI)
	}
	if after.ClientSecretHash != sha256Hex("gb-secret") {
		t.Errorf("secret hash changed to %q", after.ClientSecretHash)
	}
	if !reflect.DeepEqual(after, before) {
		t.Errorf("client record changed: before %+v, after %+v", before, after)
	}
}

func TestMCPClientInfo_ForbiddenRequestChangesNothing(t *testing.T) {
	app, router := newMCPTestApp(t)
	before := getClient(t, app, "pi-health")

	w := postMCPClient(router, "pi-health", "ph-secret", `{"redirect_uri":"https://other.example/cb"}`)
	assertRejected(t, w, http.StatusForbidden)

	if after := getClient(t, app, "pi-health"); !reflect.DeepEqual(after, before) {
		t.Errorf("client record changed: before %+v, after %+v", before, after)
	}
}

func TestMCPClientInfo_NoMCPClient(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedClient(t, app, "gamebacklog-web", "gb-secret", "http://localhost:3000/cb", "http://gb.local/backchannel")

	assertMCPCredentials(t, postMCPClient(router, "gamebacklog-web", "gb-secret", ""), "")
}
