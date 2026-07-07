package handler

import "net/http"

// GET /.well-known/jwks.json
func (a *App) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	jsonOK(w, a.Keys.JWKS())
}
