package handler

import (
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"account-manager/internal/db"
)

func TestPublicLink(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		param   string
		value   string
		want    string
		wantErr bool
	}{
		{name: "issuer with path", issuer: "https://pi.example.ts.net/accounts", param: "reset", value: "abc123",
			want: "https://pi.example.ts.net/accounts/?reset=abc123"},
		{name: "issuer with trailing slash", issuer: "https://pi.example.ts.net/accounts/", param: "reset", value: "abc123",
			want: "https://pi.example.ts.net/accounts/?reset=abc123"},
		{name: "port is kept", issuer: "http://localhost:4001", param: "invite", value: "abc123",
			want: "http://localhost:4001/accounts/?invite=abc123"},
		{name: "issuer without path", issuer: "http://localhost:3001", param: "verify-email", value: "abc123",
			want: "http://localhost:3001/accounts/?verify-email=abc123"},
		{name: "other path, query and fragment are not used", issuer: "https://app.example:8443/a/b?x=1#frag", param: "reset", value: "abc123",
			want: "https://app.example:8443/accounts/?reset=abc123"},
		{name: "value is query encoded", issuer: "https://app.example", param: "reset", value: "a b&c=d#e",
			want: "https://app.example/accounts/?reset=a+b%26c%3Dd%23e"},

		{name: "empty", issuer: "", param: "reset", value: "abc123", wantErr: true},
		{name: "no scheme", issuer: "localhost:3001", param: "reset", value: "abc123", wantErr: true},
		{name: "scheme-relative", issuer: "//app.example/accounts", param: "reset", value: "abc123", wantErr: true},
		{name: "opaque", issuer: "https:app.example", param: "reset", value: "abc123", wantErr: true},
		{name: "path only", issuer: "/accounts", param: "reset", value: "abc123", wantErr: true},
		{name: "other scheme", issuer: "ftp://host/accounts", param: "reset", value: "abc123", wantErr: true},
		{name: "no host", issuer: "https://", param: "reset", value: "abc123", wantErr: true},
		{name: "user info", issuer: "https://user:pw@host/accounts", param: "reset", value: "abc123", wantErr: true},
		{name: "unparsable", issuer: "http://host:bad port", param: "reset", value: "abc123", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := publicLink(tc.issuer, tc.param, tc.value)
			if tc.wantErr {
				if err == nil {
					t.Errorf("publicLink(%q): want error, got nil", tc.issuer)
				}
			} else if err != nil {
				t.Errorf("publicLink(%q): %v", tc.issuer, err)
			}
			if got != tc.want {
				t.Errorf("publicLink(%q) = %q, want %q", tc.issuer, got, tc.want)
			}
		})
	}
}

var otherForwardedHeaders = map[string]string{
	"X-Forwarded-Host":  "other.example",
	"X-Forwarded-Proto": "https",
}

func authHeaders(token string) map[string]string {
	h := map[string]string{"Authorization": "Bearer " + token}
	for k, v := range otherForwardedHeaders {
		h[k] = v
	}
	return h
}

func countRows(t *testing.T, app *App, query string) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func queryString(t *testing.T, app *App, query string) string {
	t.Helper()
	var s string
	if err := app.DB.QueryRow(query).Scan(&s); err != nil {
		t.Fatalf("query: %v", err)
	}
	return s
}

func seedAccountWithEmail(t *testing.T, app *App) string {
	t.Helper()
	username, _, _ := seedAccount(t, app.DB)
	if err := db.UpdateUserEmail(app.DB, username, "alice@example.com"); err != nil {
		t.Fatalf("UpdateUserEmail: %v", err)
	}
	return username
}

// captureMail points the app at a local SMTP server that accepts one message.
func captureMail(t *testing.T, app *App) <-chan string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	messages := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		tp := textproto.NewConn(conn)
		_ = tp.PrintfLine("220 localhost")
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			switch verb, _, _ := strings.Cut(line, " "); strings.ToUpper(verb) {
			case "DATA":
				_ = tp.PrintfLine("354 send data")
				data, err := tp.ReadDotBytes()
				if err != nil {
					return
				}
				messages <- string(data)
				_ = tp.PrintfLine("250 ok")
			case "QUIT":
				_ = tp.PrintfLine("221 bye")
				return
			default:
				_ = tp.PrintfLine("250 ok")
			}
		}
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	app.Cfg.SMTPHost = host
	app.Cfg.SMTPPort = port
	app.Cfg.SMTPFrom = "noreply@example.com"
	app.Cfg.SMTPTLSMode = "none"
	return messages
}

func assertMailedLink(t *testing.T, messages <-chan string, want string) {
	t.Helper()
	select {
	case msg := <-messages:
		if !strings.Contains(msg, "\n"+want+"\n") {
			t.Errorf("mail does not contain the line %q:\n%s", want, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no mail received")
	}
}

func TestAdminCreateInvite_LinkUsesIssuer(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodPost, "/api/admin/invite",
		nil, nil, authHeaders(accessToken))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	decodeJSON(t, w.Body, &resp)
	if resp.Token == "" {
		t.Fatal("empty token")
	}
	if want := "http://localhost:3001/accounts/?invite=" + resp.Token; resp.URL != want {
		t.Errorf("url = %q, want %q", resp.URL, want)
	}
}

func TestForgotPassword_LinkUsesIssuer(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccountWithEmail(t, app)
	messages := captureMail(t, app)

	w := doRequest(t, router, http.MethodPost, "/api/auth/forgot-password",
		jsonBody(t, map[string]string{"email": "alice@example.com"}),
		nil, otherForwardedHeaders)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	token := queryString(t, app, "SELECT token FROM password_reset_tokens")
	assertMailedLink(t, messages, "http://localhost:3001/accounts/?reset="+token)
}

func TestUpdateEmail_LinkUsesIssuer(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)
	messages := captureMail(t, app)

	w := doRequest(t, router, http.MethodPut, "/api/auth/email",
		jsonBody(t, map[string]string{"email": "alice@example.com"}),
		nil, authHeaders(accessToken))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	token := queryString(t, app, "SELECT token FROM email_verification_tokens")
	assertMailedLink(t, messages, "http://localhost:3001/accounts/?verify-email="+token)
}

func TestAdminCreateInvite_BadIssuer(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.JWTIssuer = "not a url"
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodPost, "/api/admin/invite",
		nil, nil, authHeaders(accessToken))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d: %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "SELECT COUNT(*) FROM pending_invites"); n != 0 {
		t.Errorf("pending_invites rows = %d, want 0", n)
	}
}

func TestForgotPassword_BadIssuerSavesNoToken(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.JWTIssuer = "not a url"
	router := buildRouter(app)
	seedAccountWithEmail(t, app)

	w := doRequest(t, router, http.MethodPost, "/api/auth/forgot-password",
		jsonBody(t, map[string]string{"email": "alice@example.com"}),
		nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got, want := strings.TrimSpace(w.Body.String()), `{"ok":true}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if n := countRows(t, app, "SELECT COUNT(*) FROM password_reset_tokens"); n != 0 {
		t.Errorf("password_reset_tokens rows = %d, want 0", n)
	}
}

func TestForgotPassword_SavesToken(t *testing.T) {
	app := newTestApp(t)
	router := buildRouter(app)
	seedAccountWithEmail(t, app)

	w := doRequest(t, router, http.MethodPost, "/api/auth/forgot-password",
		jsonBody(t, map[string]string{"email": "alice@example.com"}),
		nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "SELECT COUNT(*) FROM password_reset_tokens"); n != 1 {
		t.Errorf("password_reset_tokens rows = %d, want 1", n)
	}
}

func TestUpdateEmail_BadIssuer(t *testing.T) {
	app := newTestApp(t)
	app.Cfg.JWTIssuer = "not a url"
	router := buildRouter(app)
	username, _, _ := seedAccount(t, app.DB)
	accessToken := seedAccessToken(t, app, username)

	w := doRequest(t, router, http.MethodPut, "/api/auth/email",
		jsonBody(t, map[string]string{"email": "alice@example.com"}),
		nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d: %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "SELECT COUNT(*) FROM email_verification_tokens"); n != 0 {
		t.Errorf("email_verification_tokens rows = %d, want 0", n)
	}
}
