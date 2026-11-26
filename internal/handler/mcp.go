package handler

import (
	"net/http"

	"account-manager/internal/db"
)

// mcpClientInfoCaller is the only client that may read the claude-mcp credentials.
const mcpClientInfoCaller = "gamebacklog-web"

// POST /api/mcp-client
// Returns the claude-mcp client ID and secret so game-backlog can show them in its settings.
// Basic auth with the gamebacklog-web client credentials. Other clients get 403.
// The request body is ignored.
func (a *App) MCPClientInfo(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "credentials required")
		return
	}
	release, ok := a.reserveClientAuth(r)
	if !ok {
		tooManyAttempts(w)
		return
	}
	client, _ := db.GetOAuthClient(a.DB, clientID)
	if client == nil || !timingSafeEqual(sha256Hex(clientSecret), client.ClientSecretHash) {
		jsonErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	release()
	if client.ClientID != mcpClientInfoCaller {
		jsonErr(w, http.StatusForbidden, "client not allowed")
		return
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
