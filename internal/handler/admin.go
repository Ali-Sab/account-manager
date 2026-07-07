package handler

import (
	"fmt"
	"net/http"

	"account-manager/internal/db"

	"github.com/go-chi/chi/v5"
)

// AdminOnly is a middleware that requires the authenticated user to be an admin.
func (a *App) AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := usernameFromContext(r)
		user, _ := db.GetUser(a.DB, username)
		if user == nil || !user.IsAdmin {
			jsonErr(w, http.StatusForbidden, "Admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GET /api/auth/me  (requireAuth)
func (a *App) Me(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r)
	user, _ := db.GetUser(a.DB, username)
	if user == nil {
		jsonErr(w, http.StatusNotFound, "User not found")
		return
	}
	jsonOK(w, map[string]any{
		"username": user.Username,
		"email":    user.Email,
		"isAdmin":  user.IsAdmin,
	})
}

// GET /api/admin/users  (requireAuth + AdminOnly)
func (a *App) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, _ := db.ListUsers(a.DB)
	type view struct {
		Username  string `json:"username"`
		Email     string `json:"email"`
		IsAdmin   bool   `json:"isAdmin"`
		CreatedAt int64  `json:"createdAt"`
	}
	out := make([]view, 0, len(users))
	for _, u := range users {
		out = append(out, view{Username: u.Username, Email: u.Email, IsAdmin: u.IsAdmin, CreatedAt: u.CreatedAt})
	}
	jsonOK(w, out)
}

// DELETE /api/admin/users/:username  (requireAuth + AdminOnly)
func (a *App) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	target := chi.URLParam(r, "username")
	actor := usernameFromContext(r)
	if target == actor {
		jsonErr(w, http.StatusBadRequest, "Cannot delete your own account")
		return
	}
	if err := db.DeleteUser(a.DB, target); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}
	_ = db.DeleteRefreshTokensByUser(a.DB, target)
	_ = db.DeleteAllPasskeysByUser(a.DB, target)
	_ = db.DeleteOAuthRefreshTokensByUser(a.DB, target)
	_ = db.DeleteOAuthAuthCodesByUser(a.DB, target)
	_ = db.DeletePasswordResetTokensByUser(a.DB, target)
	_ = db.DeleteEmailVerificationsByUser(a.DB, target)
	jsonOK(w, map[string]bool{"ok": true})
}

// POST /api/admin/invite  (requireAuth + AdminOnly)
func (a *App) AdminCreateInvite(w http.ResponseWriter, r *http.Request) {
	actor := usernameFromContext(r)
	token := randomHex(32)
	if err := db.CreatePendingInvite(a.DB, token, actor); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to create invite")
		return
	}
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
	inviteURL := fmt.Sprintf("%s://%s/accounts/?invite=%s", proto, host, token)
	jsonOK(w, map[string]string{"token": token, "url": inviteURL})
}
