package setup

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"account-manager/internal/db"
	"account-manager/internal/keys"
)

// ClientURIs groups the redirect and backchannel URIs for a single OAuth client.
type ClientURIs struct {
	RedirectURI    string
	BackchannelURI string
}

// EnsureInitialized runs all idempotent startup tasks:
// 1. Generate RSA keypair if absent
// 2. DB migrations (handled by db.Open)
// 3. Seed well-known OAuth clients if absent; apply backchannel URIs to existing ones
//
// Returns a loaded KeyPair and prints newly generated credentials to stdout.
func EnsureInitialized(dataDir string, gamebacklog, serviceManager, choreChart ClientURIs, sqlDB *sql.DB) (*keys.KeyPair, error) {
	// 1. RSA keys
	kp, isNew, err := ensureKeys(dataDir)
	if err != nil {
		return nil, fmt.Errorf("RSA key setup: %w", err)
	}
	if isNew {
		fmt.Printf("[setup] RSA-2048 key pair generated in %s/keys/\n", dataDir)
	} else {
		fmt.Println("[setup] RSA keys already exist, skipping generation")
	}

	// 2. DB migrations already done by db.Open (called before this).
	fmt.Println("[setup] Database schema up to date")

	// 3. OAuth clients
	var newCreds []newCred
	if nc, err := seedMCPClient(sqlDB); err != nil {
		return nil, fmt.Errorf("seeding MCP client: %w", err)
	} else if nc != nil {
		newCreds = append(newCreds, *nc)
		fmt.Println("[setup] MCP OAuth client created")
	} else {
		fmt.Println("[setup] MCP OAuth client already exists, skipping")
	}

	if nc, err := seedGamebacklogClient(sqlDB, gamebacklog); err != nil {
		return nil, fmt.Errorf("seeding gamebacklog client: %w", err)
	} else if nc != nil {
		newCreds = append(newCreds, *nc)
		fmt.Println("[setup] Game Backlog OAuth client created")
	} else {
		fmt.Println("[setup] Game Backlog OAuth client already exists, skipping")
	}

	if nc, err := seedServiceManagerClient(sqlDB, serviceManager); err != nil {
		return nil, fmt.Errorf("seeding service-manager client: %w", err)
	} else if nc != nil {
		newCreds = append(newCreds, *nc)
		fmt.Println("[setup] Service Manager OAuth client created")
	} else {
		fmt.Println("[setup] Service Manager OAuth client already exists, skipping")
	}

	if nc, err := seedChoreChartClient(sqlDB, choreChart); err != nil {
		return nil, fmt.Errorf("seeding chore-chart client: %w", err)
	} else if nc != nil {
		newCreds = append(newCreds, *nc)
		fmt.Println("[setup] Chore Chart OAuth client created")
	} else {
		fmt.Println("[setup] Chore Chart OAuth client already exists, skipping")
	}

	if len(newCreds) > 0 {
		line := "────────────────────────────────────────────────────────────"
		fmt.Printf("\n%s\n", line)
		fmt.Println("  SAVE THESE CREDENTIALS — they will not be shown again")
		fmt.Printf("%s\n", line)
		for _, c := range newCreds {
			fmt.Printf("\n  %s\n", c.label)
			fmt.Printf("    CLIENT_ID:     %s\n", c.clientID)
			fmt.Printf("    CLIENT_SECRET: %s\n", c.clientSecret)
		}
		fmt.Printf("\n%s\n\n", line)
	}
	fmt.Println("[setup] Done.")
	return kp, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

type newCred struct {
	label        string
	clientID     string
	clientSecret string
}

func ensureKeys(dataDir string) (*keys.KeyPair, bool, error) {
	privPath := filepath.Join(dataDir, "keys", "private.pem")
	pubPath := filepath.Join(dataDir, "keys", "public.pem")
	_, errPriv := os.Stat(privPath)
	_, errPub := os.Stat(pubPath)
	if errPriv == nil && errPub == nil {
		kp, err := keys.Load(dataDir)
		return kp, false, err
	}
	kp, err := keys.Generate(dataDir)
	return kp, true, err
}

func seedMCPClient(sqlDB *sql.DB) (*newCred, error) {
	existing, err := db.GetOAuthClient(sqlDB, "claude-mcp")
	if err != nil {
		return nil, err
	}

	if existing != nil && existing.ClientSecret != "" {
		return nil, nil
	}

	// Either first run or an existing row that predates the client_secret column —
	// generate (or rotate) the secret so the plaintext is stored for display.
	secret, err := randomHex(32)
	if err != nil {
		return nil, err
	}

	redirectURIs := []string{"https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"}
	if existing != nil {
		redirectURIs = existing.RedirectURIs
	}

	if err := db.UpsertOAuthClient(sqlDB, &db.OAuthClient{
		ClientID:         "claude-mcp",
		ClientSecretHash: sha256Hex(secret),
		ClientSecret:     secret,
		RedirectURIs:     redirectURIs,
		Name:             "Claude",
		Audience:         "mcp",
	}); err != nil {
		return nil, err
	}

	label := "Claude MCP (enter these in Claude.ai → Settings → Integrations)"
	if existing != nil {
		label = "Claude MCP secret rotated — update Claude.ai → Settings → Integrations"
	}
	return &newCred{
		label:        label,
		clientID:     "claude-mcp",
		clientSecret: secret,
	}, nil
}

func seedGamebacklogClient(sqlDB *sql.DB, uris ClientURIs) (*newCred, error) {
	if uris.RedirectURI == "" {
		uris.RedirectURI = "http://localhost:3010/auth/callback"
	}
	existing, err := db.GetOAuthClient(sqlDB, "gamebacklog-web")
	if err != nil {
		return nil, err
	}

	if existing != nil {
		return applyClientURIs(sqlDB, existing, uris)
	}

	secret, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	if err := db.UpsertOAuthClient(sqlDB, &db.OAuthClient{
		ClientID:             "gamebacklog-web",
		ClientSecretHash:     sha256Hex(secret),
		ClientSecret:         secret,
		RedirectURIs:         []string{uris.RedirectURI},
		Name:                 "Game Backlog",
		Audience:             "gamebacklog",
		BackchannelLogoutURI: uris.BackchannelURI,
	}); err != nil {
		return nil, err
	}
	return &newCred{
		label:        "Game Backlog web client (copy these into gamebacklog/.env)",
		clientID:     "gamebacklog-web",
		clientSecret: secret,
	}, nil
}

func seedServiceManagerClient(sqlDB *sql.DB, uris ClientURIs) (*newCred, error) {
	if uris.RedirectURI == "" {
		uris.RedirectURI = "http://localhost:8082/oauth/callback"
	}
	existing, err := db.GetOAuthClient(sqlDB, "service-manager")
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return applyClientURIs(sqlDB, existing, uris)
	}
	secret, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	if err := db.UpsertOAuthClient(sqlDB, &db.OAuthClient{
		ClientID:             "service-manager",
		ClientSecretHash:     sha256Hex(secret),
		ClientSecret:         secret,
		RedirectURIs:         []string{uris.RedirectURI},
		Name:                 "Service Manager",
		Audience:             "service-manager",
		BackchannelLogoutURI: uris.BackchannelURI,
	}); err != nil {
		return nil, err
	}
	return &newCred{
		label:        "Service Manager web client (copy these into service-manager.env)",
		clientID:     "service-manager",
		clientSecret: secret,
	}, nil
}

func seedChoreChartClient(sqlDB *sql.DB, uris ClientURIs) (*newCred, error) {
	if uris.RedirectURI == "" {
		uris.RedirectURI = "http://localhost:8080/oauth/callback"
	}
	existing, err := db.GetOAuthClient(sqlDB, "chore-chart")
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return applyClientURIs(sqlDB, existing, uris)
	}
	secret, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	if err := db.UpsertOAuthClient(sqlDB, &db.OAuthClient{
		ClientID:             "chore-chart",
		ClientSecretHash:     sha256Hex(secret),
		ClientSecret:         secret,
		RedirectURIs:         []string{uris.RedirectURI},
		Name:                 "Chore Chart",
		Audience:             "chore-chart",
		BackchannelLogoutURI: uris.BackchannelURI,
	}); err != nil {
		return nil, err
	}
	return &newCred{
		label:        "Chore Chart web client (copy these into chore-chart.env)",
		clientID:     "chore-chart",
		clientSecret: secret,
	}, nil
}

// applyClientURIs syncs redirect_uri and backchannel_logout_uri on an existing
// client to match the current config. Returns nil, nil (no new credentials) always.
func applyClientURIs(sqlDB *sql.DB, existing *db.OAuthClient, uris ClientURIs) (*newCred, error) {
	updated := false
	if uris.RedirectURI != "" && (len(existing.RedirectURIs) != 1 || existing.RedirectURIs[0] != uris.RedirectURI) {
		existing.RedirectURIs = []string{uris.RedirectURI}
		updated = true
		fmt.Printf("[setup] Updated redirect_uri for %s\n", existing.ClientID)
	}
	if uris.BackchannelURI != "" && existing.BackchannelLogoutURI != uris.BackchannelURI {
		existing.BackchannelLogoutURI = uris.BackchannelURI
		updated = true
		fmt.Printf("[setup] Updated backchannel_logout_uri for %s\n", existing.ClientID)
	}
	if updated {
		if err := db.UpsertOAuthClient(sqlDB, existing); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
