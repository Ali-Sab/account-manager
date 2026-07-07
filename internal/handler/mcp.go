package handler

import (
	"encoding/json"
	"net/http"

	"account-manager/internal/db"
)

// POST /api/mcp-client
// Returns the claude-mcp client ID and secret so downstream services (e.g. game-backlog)
// can display them to the user without needing a separate env var.
// Authenticated via Basic auth using any registered OAuth client's credentials.
// Optional JSON body: { "redirect_uri": "..." } — if present, updates the caller's registered redirect URI.
func (a *App) MCPClientInfo(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "credentials required")
		return
	}
	client, _ := db.GetOAuthClient(a.DB, clientID)
	if client == nil || !timingSafeEqual(sha256Hex(clientSecret), client.ClientSecretHash) {
		jsonErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	var body struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.RedirectURI != "" {
		_ = db.UpsertOAuthClient(a.DB, &db.OAuthClient{
			ClientID:         client.ClientID,
			ClientSecretHash: client.ClientSecretHash,
			ClientSecret:     client.ClientSecret,
			RedirectURIs:     []string{body.RedirectURI},
			Name:             client.Name,
			Audience:         client.Audience,
		})
	}

	mcp, _ := db.GetOAuthClient(a.DB, "claude-mcp")
	mcpSecret := ""
	if mcp != nil {
		mcpSecret = mcp.ClientSecret
	}
	jsonOK(w, map[string]string{
		"client_id":     "claude-mcp",
		"client_secret": mcpSecret,
	})
}
