package setup

import (
	"database/sql"
	"reflect"
	"regexp"
	"testing"

	"account-manager/internal/db"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	return sqlDB
}

func mustGetClient(t *testing.T, sqlDB *sql.DB, id string) *db.OAuthClient {
	t.Helper()
	c, err := db.GetOAuthClient(sqlDB, id)
	if err != nil {
		t.Fatalf("GetOAuthClient(%s): %v", id, err)
	}
	if c == nil {
		t.Fatalf("client %s not found", id)
	}
	return c
}

func countClients(t *testing.T, sqlDB *sql.DB) int {
	t.Helper()
	var n int
	if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM oauth_clients`).Scan(&n); err != nil {
		t.Fatalf("count oauth_clients: %v", err)
	}
	return n
}

func TestSeedClaudePortalClientCreates(t *testing.T) {
	sqlDB := openTestDB(t)
	uri := "https://pi.example.ts.net/claude/oauth/callback"

	nc, err := seedClaudePortalClient(sqlDB, ClientURIs{RedirectURI: uri})
	if err != nil {
		t.Fatalf("seedClaudePortalClient: %v", err)
	}
	if nc == nil {
		t.Fatal("expected new credentials, got nil")
	}
	if nc.clientID != "claude-portal" {
		t.Errorf("clientID = %q, want claude-portal", nc.clientID)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(nc.clientSecret) {
		t.Errorf("clientSecret %q is not 64 lowercase hex chars", nc.clientSecret)
	}

	c := mustGetClient(t, sqlDB, "claude-portal")
	if c.Audience != "claude-portal" {
		t.Errorf("Audience = %q, want claude-portal", c.Audience)
	}
	if c.Name != "Claude Portal" {
		t.Errorf("Name = %q, want Claude Portal", c.Name)
	}
	if !reflect.DeepEqual(c.RedirectURIs, []string{uri}) {
		t.Errorf("RedirectURIs = %v, want [%s]", c.RedirectURIs, uri)
	}
	if c.BackchannelLogoutURI != "" {
		t.Errorf("BackchannelLogoutURI = %q, want empty", c.BackchannelLogoutURI)
	}
	if c.ClientSecretHash != sha256Hex(nc.clientSecret) {
		t.Errorf("ClientSecretHash = %q, want sha256 of the secret", c.ClientSecretHash)
	}
	if c.ClientSecret != nc.clientSecret {
		t.Errorf("stored ClientSecret does not match the returned secret")
	}
}

func TestSeedClaudePortalClientDefault(t *testing.T) {
	sqlDB := openTestDB(t)

	nc, err := seedClaudePortalClient(sqlDB, ClientURIs{})
	if err != nil {
		t.Fatalf("seedClaudePortalClient: %v", err)
	}
	if nc == nil {
		t.Fatal("expected new credentials, got nil")
	}
	c := mustGetClient(t, sqlDB, "claude-portal")
	want := []string{"http://localhost:7681/oauth/callback"}
	if !reflect.DeepEqual(c.RedirectURIs, want) {
		t.Errorf("RedirectURIs = %v, want %v", c.RedirectURIs, want)
	}
}

func TestSeedClaudePortalClientResync(t *testing.T) {
	sqlDB := openTestDB(t)
	a := "https://a.example.ts.net/claude/oauth/callback"
	b := "https://b.example.ts.net/claude/oauth/callback"

	if nc, err := seedClaudePortalClient(sqlDB, ClientURIs{RedirectURI: a}); err != nil || nc == nil {
		t.Fatalf("first seed: nc=%v err=%v", nc, err)
	}

	c := mustGetClient(t, sqlDB, "claude-portal")
	c.ClientSecretHash = "rotated"
	if err := db.UpsertOAuthClient(sqlDB, c); err != nil {
		t.Fatalf("UpsertOAuthClient: %v", err)
	}

	nc, err := seedClaudePortalClient(sqlDB, ClientURIs{RedirectURI: b})
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if nc != nil {
		t.Errorf("second seed returned credentials %+v, want nil", nc)
	}
	got := mustGetClient(t, sqlDB, "claude-portal")
	if !reflect.DeepEqual(got.RedirectURIs, []string{b}) {
		t.Errorf("RedirectURIs = %v, want [%s]", got.RedirectURIs, b)
	}
	if got.ClientSecretHash != "rotated" {
		t.Errorf("ClientSecretHash = %q, want rotated (kept)", got.ClientSecretHash)
	}
}

func TestSeedClaudePortalClientIdempotent(t *testing.T) {
	sqlDB := openTestDB(t)
	uri := "https://pi.example.ts.net/claude/oauth/callback"

	if nc, err := seedClaudePortalClient(sqlDB, ClientURIs{RedirectURI: uri}); err != nil || nc == nil {
		t.Fatalf("first seed: nc=%v err=%v", nc, err)
	}
	first := mustGetClient(t, sqlDB, "claude-portal")

	nc, err := seedClaudePortalClient(sqlDB, ClientURIs{RedirectURI: uri})
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if nc != nil {
		t.Errorf("second seed returned credentials %+v, want nil", nc)
	}
	second := mustGetClient(t, sqlDB, "claude-portal")
	if !reflect.DeepEqual(first, second) {
		t.Errorf("row changed on second seed: %+v -> %+v", first, second)
	}
	if n := countClients(t, sqlDB); n != 1 {
		t.Errorf("oauth_clients rows = %d, want 1", n)
	}
}

func TestSeedPiHealthClientCreates(t *testing.T) {
	sqlDB := openTestDB(t)
	uri := "https://pi.example.ts.net/health/oauth/callback"
	bc := "http://pi-health:8084/health/api/auth/backchannel-logout"

	nc, err := seedPiHealthClient(sqlDB, ClientURIs{RedirectURI: uri, BackchannelURI: bc})
	if err != nil {
		t.Fatalf("seedPiHealthClient: %v", err)
	}
	if nc == nil {
		t.Fatal("expected new credentials, got nil")
	}
	if nc.clientID != "pi-health" {
		t.Errorf("clientID = %q, want pi-health", nc.clientID)
	}
	if want := "Pi Health web client (copy these into homelab-infra env/pi-health.env)"; nc.label != want {
		t.Errorf("label = %q, want %q", nc.label, want)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(nc.clientSecret) {
		t.Errorf("clientSecret %q is not 64 lowercase hex chars", nc.clientSecret)
	}

	c := mustGetClient(t, sqlDB, "pi-health")
	if c.Audience != "pi-health" {
		t.Errorf("Audience = %q, want pi-health", c.Audience)
	}
	if c.Name != "Pi Health" {
		t.Errorf("Name = %q, want Pi Health", c.Name)
	}
	if !reflect.DeepEqual(c.RedirectURIs, []string{uri}) {
		t.Errorf("RedirectURIs = %v, want [%s]", c.RedirectURIs, uri)
	}
	if c.BackchannelLogoutURI != bc {
		t.Errorf("BackchannelLogoutURI = %q, want %q", c.BackchannelLogoutURI, bc)
	}
	if c.ClientSecretHash != sha256Hex(nc.clientSecret) {
		t.Errorf("ClientSecretHash = %q, want sha256 of the secret", c.ClientSecretHash)
	}
	if c.ClientSecret != nc.clientSecret {
		t.Errorf("stored ClientSecret does not match the returned secret")
	}
}

func TestSeedPiHealthClientDefault(t *testing.T) {
	sqlDB := openTestDB(t)

	nc, err := seedPiHealthClient(sqlDB, ClientURIs{})
	if err != nil {
		t.Fatalf("seedPiHealthClient: %v", err)
	}
	if nc == nil {
		t.Fatal("expected new credentials, got nil")
	}
	c := mustGetClient(t, sqlDB, "pi-health")
	want := []string{"http://localhost:8084/health/oauth/callback"}
	if !reflect.DeepEqual(c.RedirectURIs, want) {
		t.Errorf("RedirectURIs = %v, want %v", c.RedirectURIs, want)
	}
	if c.BackchannelLogoutURI != "" {
		t.Errorf("BackchannelLogoutURI = %q, want empty", c.BackchannelLogoutURI)
	}
}

func TestSeedPiHealthClientResync(t *testing.T) {
	sqlDB := openTestDB(t)
	a := ClientURIs{
		RedirectURI:    "https://a.example.ts.net/health/oauth/callback",
		BackchannelURI: "http://bc1:8084/health/api/auth/backchannel-logout",
	}
	b := ClientURIs{
		RedirectURI:    "https://b.example.ts.net/health/oauth/callback",
		BackchannelURI: "http://bc2:8084/health/api/auth/backchannel-logout",
	}

	if nc, err := seedPiHealthClient(sqlDB, a); err != nil || nc == nil {
		t.Fatalf("first seed: nc=%v err=%v", nc, err)
	}

	c := mustGetClient(t, sqlDB, "pi-health")
	c.ClientSecretHash = "rotated"
	if err := db.UpsertOAuthClient(sqlDB, c); err != nil {
		t.Fatalf("UpsertOAuthClient: %v", err)
	}

	nc, err := seedPiHealthClient(sqlDB, b)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if nc != nil {
		t.Errorf("second seed returned credentials %+v, want nil", nc)
	}
	got := mustGetClient(t, sqlDB, "pi-health")
	if !reflect.DeepEqual(got.RedirectURIs, []string{b.RedirectURI}) {
		t.Errorf("RedirectURIs = %v, want [%s]", got.RedirectURIs, b.RedirectURI)
	}
	if got.BackchannelLogoutURI != b.BackchannelURI {
		t.Errorf("BackchannelLogoutURI = %q, want %q", got.BackchannelLogoutURI, b.BackchannelURI)
	}
	if got.ClientSecretHash != "rotated" {
		t.Errorf("ClientSecretHash = %q, want rotated (kept)", got.ClientSecretHash)
	}
}

func TestSeedPiHealthClientResyncKeepsBackchannelWhenEmpty(t *testing.T) {
	sqlDB := openTestDB(t)
	uri := "https://pi.example.ts.net/health/oauth/callback"
	bc := "http://pi-health:8084/health/api/auth/backchannel-logout"

	if nc, err := seedPiHealthClient(sqlDB, ClientURIs{RedirectURI: uri, BackchannelURI: bc}); err != nil || nc == nil {
		t.Fatalf("first seed: nc=%v err=%v", nc, err)
	}
	if nc, err := seedPiHealthClient(sqlDB, ClientURIs{RedirectURI: uri}); err != nil || nc != nil {
		t.Fatalf("second seed: nc=%v err=%v, want nil, nil", nc, err)
	}
	if got := mustGetClient(t, sqlDB, "pi-health"); got.BackchannelLogoutURI != bc {
		t.Errorf("BackchannelLogoutURI = %q, want %q (kept)", got.BackchannelLogoutURI, bc)
	}
}

func TestSeedPiHealthClientIdempotent(t *testing.T) {
	sqlDB := openTestDB(t)
	uris := ClientURIs{
		RedirectURI:    "https://pi.example.ts.net/health/oauth/callback",
		BackchannelURI: "http://pi-health:8084/health/api/auth/backchannel-logout",
	}

	if nc, err := seedPiHealthClient(sqlDB, uris); err != nil || nc == nil {
		t.Fatalf("first seed: nc=%v err=%v", nc, err)
	}
	first := mustGetClient(t, sqlDB, "pi-health")

	nc, err := seedPiHealthClient(sqlDB, uris)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if nc != nil {
		t.Errorf("second seed returned credentials %+v, want nil", nc)
	}
	second := mustGetClient(t, sqlDB, "pi-health")
	if !reflect.DeepEqual(first, second) {
		t.Errorf("row changed on second seed: %+v -> %+v", first, second)
	}
	if n := countClients(t, sqlDB); n != 1 {
		t.Errorf("oauth_clients rows = %d, want 1", n)
	}
}

func TestEnsureInitializedPassesPiHealthURIs(t *testing.T) {
	sqlDB := openTestDB(t)
	dataDir := t.TempDir()
	none := ClientURIs{}
	portal := ClientURIs{RedirectURI: "https://pi.example.ts.net/claude/oauth/callback"}

	// The second pass changes the URIs, to check the re-sync at start.
	for _, host := range []string{"a", "b"} {
		health := ClientURIs{
			RedirectURI:    "https://" + host + ".example.ts.net/health/oauth/callback",
			BackchannelURI: "http://" + host + ":8084/health/api/auth/backchannel-logout",
		}
		if _, err := EnsureInitialized(dataDir, none, none, none, portal, health, sqlDB); err != nil {
			t.Fatalf("EnsureInitialized(%s): %v", host, err)
		}

		got := mustGetClient(t, sqlDB, "pi-health")
		if !reflect.DeepEqual(got.RedirectURIs, []string{health.RedirectURI}) {
			t.Errorf("pi-health RedirectURIs = %v, want [%s]", got.RedirectURIs, health.RedirectURI)
		}
		if got.BackchannelLogoutURI != health.BackchannelURI {
			t.Errorf("pi-health BackchannelLogoutURI = %q, want %q", got.BackchannelLogoutURI, health.BackchannelURI)
		}
		other := mustGetClient(t, sqlDB, "claude-portal")
		if !reflect.DeepEqual(other.RedirectURIs, []string{portal.RedirectURI}) {
			t.Errorf("claude-portal RedirectURIs = %v, want [%s]", other.RedirectURIs, portal.RedirectURI)
		}
		if other.BackchannelLogoutURI != "" {
			t.Errorf("claude-portal BackchannelLogoutURI = %q, want empty", other.BackchannelLogoutURI)
		}
	}
}

func TestEnsureInitializedSeedsAllClients(t *testing.T) {
	sqlDB := openTestDB(t)
	dataDir := t.TempDir()
	none := ClientURIs{}

	if _, err := EnsureInitialized(dataDir, none, none, none, none, none, sqlDB); err != nil {
		t.Fatalf("EnsureInitialized: %v", err)
	}
	ids := []string{"claude-mcp", "gamebacklog-web", "service-manager", "chore-chart", "claude-portal", "pi-health"}
	for _, id := range ids {
		c, err := db.GetOAuthClient(sqlDB, id)
		if err != nil {
			t.Fatalf("GetOAuthClient(%s): %v", id, err)
		}
		if c == nil {
			t.Errorf("client %s missing after EnsureInitialized", id)
		}
	}
	if n := countClients(t, sqlDB); n != 6 {
		t.Errorf("oauth_clients rows = %d, want 6", n)
	}

	if _, err := EnsureInitialized(dataDir, none, none, none, none, none, sqlDB); err != nil {
		t.Fatalf("second EnsureInitialized: %v", err)
	}
	if n := countClients(t, sqlDB); n != 6 {
		t.Errorf("oauth_clients rows after second call = %d, want 6", n)
	}
}
