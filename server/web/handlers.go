package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devsigner9920/ethsy-ssh/server/auth"
	"github.com/devsigner9920/ethsy-ssh/server/session"
)

// --- Helper Functions ---

// jsonResponse writes a JSON response with the given status code.
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Printf("[web] failed to encode JSON response: %v", err)
		}
	}
}

// jsonError writes a JSON error response.
func jsonError(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

// requireLocalhost returns a handler that only allows requests from 127.0.0.1.
func (s *Server) requireLocalhost(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if host != "127.0.0.1" && host != "::1" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// authenticateRequest validates the JWT token and returns the user's email.
// Returns empty string and writes error response if authentication fails.
func (s *Server) authenticateRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	tokenStr := auth.ExtractBearerToken(r)
	if tokenStr == "" {
		jsonError(w, http.StatusUnauthorized, "missing or invalid authorization header")
		return "", false
	}

	claims, err := s.auth.ValidateToken(tokenStr)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid or expired token")
		return "", false
	}

	return claims.Email, true
}

// computeFingerprint computes a simple fingerprint from a public key string.
// In production you'd use ssh.ParsePublicKey, but this avoids the dependency
// on golang.org/x/crypto/ssh for parsing. We use the key content itself as
// a stable identifier.
func computeFingerprint(publicKey string) string {
	// Use the key data portion (second field) as fingerprint base.
	parts := strings.Fields(publicKey)
	if len(parts) >= 2 {
		return "SHA256:" + parts[1][:min(43, len(parts[1]))]
	}
	return "SHA256:" + publicKey[:min(43, len(publicKey))]
}

// --- Auth Handlers ---

// handleAuth starts the OAuth flow. CLI opens browser to this URL with session query param.
// GET /auth?session={session_id}
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "missing session parameter", http.StatusBadRequest)
		return
	}

	// Store auth session in DB with 2-minute expiry.
	expiresAt := time.Now().Add(2 * time.Minute)
	if err := s.db.CreateAuthSession(sessionID, expiresAt); err != nil {
		log.Printf("[web] failed to create auth session: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Get Google OAuth URL with CSRF state.
	authURL, err := s.auth.GetAuthURL(sessionID)
	if err != nil {
		log.Printf("[web] failed to generate auth URL: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleAuthCallback processes the Google OAuth callback.
// GET /auth/callback?code={code}&state={state}
func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code and validate state.
	email, sessionID, err := s.auth.ExchangeCode(r.Context(), code, state)
	if err != nil {
		log.Printf("[web] OAuth exchange failed: %v", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Check email whitelist.
	if !s.auth.IsEmailAllowed(email) {
		log.Printf("[web] email not in whitelist: %s", email)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>ethsy - Access Denied</title></head>
<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
<h1>Access Denied</h1>
<p>%s is not authorized. Please contact the administrator.</p>
</body></html>`, email)
		return
	}

	// Generate JWT token.
	token, err := s.auth.GenerateToken(email)
	if err != nil {
		log.Printf("[web] failed to generate JWT: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Store token in the auth session for CLI polling.
	if err := s.db.SetAuthSessionToken(sessionID, token); err != nil {
		log.Printf("[web] failed to set auth session token: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] user authenticated: %s (session: %s)", email, sessionID)

	// Show success page.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>ethsy - Authentication Complete</title></head>
<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
<h1>Authentication Complete!</h1>
<p>You can close this window and return to the terminal.</p>
</body></html>`)
}

// handleAuthPoll allows the CLI to poll for authentication completion.
// GET /api/auth/poll?session={session_id}
func (s *Server) handleAuthPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		jsonError(w, http.StatusBadRequest, "missing session parameter")
		return
	}

	// Try to consume the auth session (one-time use).
	token, err := s.db.ConsumeAuthSession(sessionID)
	if err != nil {
		jsonError(w, http.StatusNotFound, "session not found or expired")
		return
	}

	if token == "" {
		// Still pending.
		jsonResponse(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}

	// Authentication complete.
	jsonResponse(w, http.StatusOK, map[string]string{
		"status": "complete",
		"token":  token,
	})
}

// --- API Handlers ---

// handleMe returns the current user's info.
// GET /api/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	user, err := s.db.GetUserByEmail(email)
	if err != nil {
		log.Printf("[web] failed to get user: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if user == nil {
		// New user, not registered yet.
		jsonError(w, http.StatusNotFound, "user not registered")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"email":    user.Email,
		"username": user.Username,
	})
}

// handleRegister handles first-time user registration.
// POST /api/register
// Body: {"username": "...", "public_key": "ssh-ed25519 ..."}
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	var req struct {
		Username  string `json:"username"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.PublicKey == "" {
		jsonError(w, http.StatusBadRequest, "username and public_key are required")
		return
	}

	// Check if user already exists.
	existing, err := s.db.GetUserByEmail(email)
	if err != nil {
		log.Printf("[web] failed to check user: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if existing != nil {
		jsonError(w, http.StatusConflict, "user already registered")
		return
	}

	// Check username uniqueness.
	existingByName, err := s.db.GetUserByUsername(req.Username)
	if err != nil {
		log.Printf("[web] failed to check username: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if existingByName != nil {
		jsonError(w, http.StatusConflict, "username already taken")
		return
	}

	// Determine if user is admin.
	isAdmin := s.auth.IsEmailAllowed(email) // All whitelisted users start; admin check from config.

	// Create user.
	userID, err := s.db.CreateUser(email, req.Username, isAdmin)
	if err != nil {
		log.Printf("[web] failed to create user: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Create user home directory.
	if err := session.EnsureUserHome(req.Username); err != nil {
		log.Printf("[web] failed to create home directory: %v", err)
		// Non-fatal, continue.
	}

	// Register SSH key.
	fingerprint := computeFingerprint(req.PublicKey)
	deviceName := extractDeviceName(req.PublicKey)
	expiresAt := time.Now().Add(s.auth.GetTokenExpiry())

	keyID, err := s.db.CreateSSHKey(userID, req.PublicKey, fingerprint, deviceName, expiresAt)
	if err != nil {
		log.Printf("[web] failed to create SSH key: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Add key to authorized_keys.
	if err := s.sshMgr.AddKey(userID, keyID, req.PublicKey); err != nil {
		log.Printf("[web] failed to add key to authorized_keys: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	log.Printf("[web] user registered: %s (%s), key_id=%d", email, req.Username, keyID)

	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"email":    email,
		"username": req.Username,
	})
}

// handleRegisterKey handles adding a new SSH key for an existing user (new device).
// POST /api/register-key
// Body: {"public_key": "ssh-ed25519 ..."}
func (s *Server) handleRegisterKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	user, err := s.db.GetUserByEmail(email)
	if err != nil {
		log.Printf("[web] failed to get user: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if user == nil {
		jsonError(w, http.StatusNotFound, "user not registered")
		return
	}

	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PublicKey == "" {
		jsonError(w, http.StatusBadRequest, "public_key is required")
		return
	}

	// Check max keys per user.
	keyCount, err := s.db.CountSSHKeysByUserID(user.ID)
	if err != nil {
		log.Printf("[web] failed to count keys: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if keyCount >= s.cfg.SSH.MaxKeysPerUser {
		jsonError(w, http.StatusConflict, fmt.Sprintf("maximum %d keys per user reached", s.cfg.SSH.MaxKeysPerUser))
		return
	}

	// Check fingerprint uniqueness.
	fingerprint := computeFingerprint(req.PublicKey)
	existingKey, err := s.db.GetSSHKeyByFingerprint(fingerprint)
	if err != nil {
		log.Printf("[web] failed to check fingerprint: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if existingKey != nil {
		jsonError(w, http.StatusConflict, "key already registered")
		return
	}

	deviceName := extractDeviceName(req.PublicKey)
	expiresAt := time.Now().Add(s.auth.GetTokenExpiry())

	keyID, err := s.db.CreateSSHKey(user.ID, req.PublicKey, fingerprint, deviceName, expiresAt)
	if err != nil {
		log.Printf("[web] failed to create SSH key: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Add key to authorized_keys.
	if err := s.sshMgr.AddKey(user.ID, keyID, req.PublicKey); err != nil {
		log.Printf("[web] failed to add key to authorized_keys: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	log.Printf("[web] key registered for user %s: key_id=%d, device=%s", email, keyID, deviceName)

	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"key_id":      keyID,
		"device_name": deviceName,
		"fingerprint": fingerprint,
	})
}

// handleRevokeKey removes an SSH key for the current user.
// POST /api/revoke-key
// Body: {"fingerprint": "..."}
func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	user, err := s.db.GetUserByEmail(email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Fingerprint == "" {
		jsonError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}

	// Find the key.
	key, err := s.db.GetSSHKeyByFingerprint(req.Fingerprint)
	if err != nil {
		log.Printf("[web] failed to get key: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if key == nil || key.UserID != user.ID {
		jsonError(w, http.StatusNotFound, "key not found")
		return
	}

	// Remove from authorized_keys.
	if err := s.sshMgr.RemoveKeyByID(user.ID, key.ID); err != nil {
		log.Printf("[web] failed to remove key from authorized_keys: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Delete from DB.
	if err := s.db.DeleteSSHKey(key.ID); err != nil {
		log.Printf("[web] failed to delete key: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	log.Printf("[web] key revoked for user %s: key_id=%d", email, key.ID)

	jsonResponse(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleSessions handles session listing and creation.
// GET /api/sessions - List sessions
// POST /api/sessions - Create session
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListSessions(w, r)
	case http.MethodPost:
		s.handleCreateSession(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	email, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	user, err := s.db.GetUserByEmail(email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	sessions, err := s.sessMgr.List(user.ID)
	if err != nil {
		log.Printf("[web] failed to list sessions: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	type sessionResp struct {
		ID           int64  `json:"id"`
		TmuxName     string `json:"tmux_name"`
		Description  string `json:"description"`
		Status       string `json:"status"`
		CreatedAt    string `json:"created_at"`
		LastAttached string `json:"last_attached"`
	}

	resp := make([]sessionResp, 0, len(sessions))
	for _, sess := range sessions {
		if !s.sessMgr.IsAlive(sess.TmuxName) {
			// Auto-cleanup stopped sessions
			if err := s.db.DeleteSession(sess.ID); err != nil {
				log.Printf("[web] failed to cleanup stopped session %s: %v", sess.TmuxName, err)
			} else {
				log.Printf("[web] auto-cleaned stopped session %s (id=%d)", sess.TmuxName, sess.ID)
			}
			continue
		}
		resp = append(resp, sessionResp{
			ID:           sess.ID,
			TmuxName:     sess.TmuxName,
			Description:  sess.Description,
			Status:       "active",
			CreatedAt:    sess.CreatedAt.Format(time.RFC3339),
			LastAttached: sess.LastAttached.Format(time.RFC3339),
		})
	}

	jsonResponse(w, http.StatusOK, resp)
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	email, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	user, err := s.db.GetUserByEmail(email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	var req struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body.
		req.Description = ""
	}

	sess, err := s.sessMgr.Create(user.ID, user.Username, req.Description)
	if err != nil {
		log.Printf("[web] failed to create session: %v", err)
		jsonError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"id":          sess.ID,
		"tmux_name":   sess.TmuxName,
		"description": sess.Description,
		"ssh_command": fmt.Sprintf("ssh -t -p %d ethsy@%s \"bash -l -c 'tmux attach -t %s'\"", s.cfg.SSH.Port, s.cfg.SSHDomain, sess.TmuxName),
	})
}

// handleSessionByID handles DELETE /api/sessions/:id
func (s *Server) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email, ok := s.authenticateRequest(w, r)
	if !ok {
		return
	}

	user, err := s.db.GetUserByEmail(email)
	if err != nil || user == nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	// Extract session ID from path: /api/sessions/{id}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	sessionID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	// Verify ownership.
	sess, err := s.db.GetSessionByID(sessionID)
	if err != nil {
		log.Printf("[web] failed to get session: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if sess == nil || sess.UserID != user.ID {
		jsonError(w, http.StatusNotFound, "session not found")
		return
	}

	if err := s.sessMgr.Delete(sessionID); err != nil {
		log.Printf("[web] failed to delete session: %v", err)
		jsonError(w, http.StatusInternalServerError, "failed to delete session")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Admin Handlers ---

// adminSharedCSS returns the shared CSS block used across all admin pages.
const adminSharedCSS = `
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; }
nav { background: #111; border-bottom: 1px solid #222; padding: 0 32px; display: flex; align-items: center; gap: 8px; height: 52px; }
nav .brand { font-weight: 700; font-size: 1.1rem; color: #fff; margin-right: 24px; letter-spacing: -0.5px; }
nav a { color: #888; text-decoration: none; padding: 6px 14px; border-radius: 6px; font-size: 0.9rem; transition: color 0.15s, background 0.15s; }
nav a:hover { color: #e0e0e0; background: #1a1a1a; }
nav a.active { color: #4a9eff; background: #0d1f3c; }
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
h1 { font-size: 1.5rem; font-weight: 600; color: #fff; margin-bottom: 24px; }
h2 { font-size: 1.1rem; font-weight: 600; color: #ccc; margin-bottom: 16px; }
.card { background: #111; border: 1px solid #222; border-radius: 10px; padding: 24px; margin-bottom: 24px; }
.stats { display: flex; gap: 20px; flex-wrap: wrap; }
.stat { background: #0d0d0d; border: 1px solid #222; border-radius: 8px; padding: 20px 28px; min-width: 160px; }
.stat .label { font-size: 0.8rem; color: #666; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
.stat .value { font-size: 2rem; font-weight: 700; color: #4a9eff; }
table { width: 100%%; border-collapse: collapse; }
th { text-align: left; padding: 10px 14px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #666; border-bottom: 1px solid #222; font-weight: 600; }
td { padding: 12px 14px; border-bottom: 1px solid #1a1a1a; font-size: 0.9rem; color: #ccc; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #141414; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
.badge-admin { background: #1a2a1a; color: #4ade80; border: 1px solid #2a4a2a; }
.badge-active { background: #0d2a1a; color: #4ade80; border: 1px solid #1a4a2a; }
.badge-stopped { background: #1a1a1a; color: #666; border: 1px solid #2a2a2a; }
.btn { display: inline-block; padding: 6px 14px; border-radius: 6px; font-size: 0.85rem; font-weight: 500; cursor: pointer; border: none; text-decoration: none; transition: opacity 0.15s; }
.btn:hover { opacity: 0.8; }
.btn-danger { background: #7f1d1d; color: #fca5a5; }
.btn-primary { background: #1d4ed8; color: #bfdbfe; }
.form-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
input[type=email], input[type=text] { background: #0d0d0d; border: 1px solid #333; border-radius: 6px; color: #e0e0e0; padding: 8px 12px; font-size: 0.9rem; outline: none; transition: border-color 0.15s; }
input[type=email]:focus, input[type=text]:focus { border-color: #4a9eff; }
.msg { padding: 10px 14px; border-radius: 6px; font-size: 0.85rem; margin-bottom: 16px; display: none; }
.msg-ok { background: #0d2a1a; color: #4ade80; border: 1px solid #1a4a2a; }
.msg-err { background: #2a0d0d; color: #fca5a5; border: 1px solid #4a1a1a; }
`

// adminNav returns the HTML nav bar, marking the active page.
func adminNav(active string) string {
	pages := []struct{ href, label string }{
		{"/admin", "Dashboard"},
		{"/admin/users", "Users"},
		{"/admin/sessions", "Sessions"},
	}
	nav := `<nav><span class="brand">ethsy admin</span>`
	for _, p := range pages {
		cls := ""
		if p.href == active {
			cls = ` class="active"`
		}
		nav += fmt.Sprintf(`<a href="%s"%s>%s</a>`, p.href, cls, p.label)
	}
	nav += `</nav>`
	return nav
}

// handleAdmin serves the admin dashboard.
// GET /admin
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users, err := s.db.ListUsers()
	if err != nil {
		log.Printf("[web] failed to list users: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	sessions, err := s.db.ListAllSessions()
	if err != nil {
		log.Printf("[web] failed to list sessions: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	activeSessions := 0
	for _, sess := range sessions {
		if s.sessMgr.IsAlive(sess.TmuxName) {
			activeSessions++
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ethsy - Admin Dashboard</title>
<style>%s</style>
</head>
<body>
%s
<div class="container">
<h1>Dashboard</h1>
<div class="card">
<h2>Overview</h2>
<div class="stats">
<div class="stat"><div class="label">Total Users</div><div class="value">%d</div></div>
<div class="stat"><div class="label">Active Sessions</div><div class="value">%d</div></div>
<div class="stat"><div class="label">Total Sessions</div><div class="value">%d</div></div>
</div>
</div>
</div>
</body>
</html>`, adminSharedCSS, adminNav("/admin"), len(users), activeSessions, len(sessions))
}

// handleAdminUsers manages the user whitelist.
// GET /admin/users - List users
// POST /admin/users - Add user email to whitelist
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAdminListUsers(w, r)
	case http.MethodPost:
		s.handleAdminAddUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers()
	if err != nil {
		log.Printf("[web] failed to list users: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Return JSON if client explicitly requests it.
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		type userResp struct {
			ID        int64  `json:"id"`
			Email     string `json:"email"`
			Username  string `json:"username"`
			IsAdmin   bool   `json:"is_admin"`
			CreatedAt string `json:"created_at"`
		}
		resp := make([]userResp, 0, len(users))
		for _, u := range users {
			resp = append(resp, userResp{
				ID:        u.ID,
				Email:     u.Email,
				Username:  u.Username,
				IsAdmin:   u.IsAdmin,
				CreatedAt: u.CreatedAt.Format(time.RFC3339),
			})
		}
		jsonResponse(w, http.StatusOK, resp)
		return
	}

	// Build user table rows.
	rows := ""
	for _, u := range users {
		adminBadge := ""
		if u.IsAdmin {
			adminBadge = ` <span class="badge badge-admin">admin</span>`
		}
		rows += fmt.Sprintf(`<tr>
<td>%d</td>
<td>%s%s</td>
<td>%s</td>
<td>%s</td>
<td><button class="btn btn-danger" onclick="deleteUser(%d, '%s')">Delete</button></td>
</tr>`, u.ID, u.Email, adminBadge, u.Username, u.CreatedAt.Format("2006-01-02 15:04"), u.ID, u.Email)
	}
	if rows == "" {
		rows = `<tr><td colspan="5" style="text-align:center;color:#555;padding:32px;">No users yet.</td></tr>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ethsy - Admin Users</title>
<style>%s</style>
</head>
<body>
%s
<div class="container">
<h1>Users</h1>
<div class="card">
<h2>Add Email to Whitelist</h2>
<div id="msg" class="msg"></div>
<div class="form-row">
<input type="email" id="emailInput" placeholder="user@example.com" style="flex:1;min-width:220px;">
<button class="btn btn-primary" onclick="addUser()">Add to Whitelist</button>
</div>
</div>
<div class="card">
<h2>Registered Users</h2>
<table>
<thead><tr><th>#</th><th>Email</th><th>Username</th><th>Created</th><th>Actions</th></tr></thead>
<tbody>%s</tbody>
</table>
</div>
</div>
<script>
function showMsg(text, ok) {
  var el = document.getElementById('msg');
  el.textContent = text;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err');
  el.style.display = 'block';
  setTimeout(function(){ el.style.display = 'none'; }, 4000);
}
function addUser() {
  var email = document.getElementById('emailInput').value.trim();
  if (!email) { showMsg('Please enter an email address.', false); return; }
  fetch('/admin/users', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: email})
  }).then(function(r){ return r.json(); }).then(function(d){
    if (d.status === 'added') { showMsg('Added: ' + d.email, true); document.getElementById('emailInput').value = ''; }
    else { showMsg('Error: ' + JSON.stringify(d), false); }
  }).catch(function(e){ showMsg('Request failed: ' + e, false); });
}
function deleteUser(id, email) {
  if (!confirm('Delete user ' + email + '?\nThis removes all their SSH keys and sessions.')) return;
  fetch('/admin/users/' + id, {method: 'DELETE'})
    .then(function(r){ return r.json(); }).then(function(d){
      if (d.status === 'deleted') { location.reload(); }
      else { alert('Error: ' + JSON.stringify(d)); }
    }).catch(function(e){ alert('Request failed: ' + e); });
}
</script>
</body>
</html>`, adminSharedCSS, adminNav("/admin/users"), rows)
}

func (s *Server) handleAdminAddUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		jsonError(w, http.StatusBadRequest, "email is required")
		return
	}

	// Add to whitelist.
	s.auth.AddAllowedEmail(req.Email)

	log.Printf("[admin] added email to whitelist: %s", req.Email)

	jsonResponse(w, http.StatusCreated, map[string]string{
		"status": "added",
		"email":  req.Email,
	})
}

// handleAdminUserByID handles DELETE /admin/users/:id
func (s *Server) handleAdminUserByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract user ID from path: /admin/users/{id}
	idStr := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	user, err := s.db.GetUserByID(userID)
	if err != nil {
		log.Printf("[web] failed to get user: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if user == nil {
		jsonError(w, http.StatusNotFound, "user not found")
		return
	}

	// Remove all SSH keys from authorized_keys.
	if err := s.sshMgr.RemoveAllKeysForUser(userID); err != nil {
		log.Printf("[web] failed to remove keys for user %d: %v", userID, err)
	}

	// Kill and remove all sessions.
	if err := s.sessMgr.DeleteAllForUser(userID); err != nil {
		log.Printf("[web] failed to delete sessions for user %d: %v", userID, err)
	}

	// Remove from whitelist.
	s.auth.RemoveAllowedEmail(user.Email)

	// Delete user (cascades to ssh_keys and sessions in DB).
	if err := s.db.DeleteUser(userID); err != nil {
		log.Printf("[web] failed to delete user: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	log.Printf("[admin] deleted user: %s (id=%d)", user.Email, userID)

	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleAdminSessions shows all sessions across all users.
// GET /admin/sessions
func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessions, err := s.db.ListAllSessions()
	if err != nil {
		log.Printf("[web] failed to list sessions: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Return JSON if client explicitly requests it.
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		type sessionResp struct {
			ID           int64  `json:"id"`
			UserID       int64  `json:"user_id"`
			TmuxName     string `json:"tmux_name"`
			Description  string `json:"description"`
			CreatedAt    string `json:"created_at"`
			LastAttached string `json:"last_attached"`
		}
		resp := make([]sessionResp, 0, len(sessions))
		for _, sess := range sessions {
			resp = append(resp, sessionResp{
				ID:           sess.ID,
				UserID:       sess.UserID,
				TmuxName:     sess.TmuxName,
				Description:  sess.Description,
				CreatedAt:    sess.CreatedAt.Format(time.RFC3339),
				LastAttached: sess.LastAttached.Format(time.RFC3339),
			})
		}
		jsonResponse(w, http.StatusOK, resp)
		return
	}

	// Look up user emails for display.
	userEmails := make(map[int64]string)
	users, err := s.db.ListUsers()
	if err == nil {
		for _, u := range users {
			userEmails[u.ID] = u.Email
		}
	}

	// Build session table rows.
	rows := ""
	for _, sess := range sessions {
		alive := s.sessMgr.IsAlive(sess.TmuxName)
		statusBadge := `<span class="badge badge-stopped">stopped</span>`
		if alive {
			statusBadge = `<span class="badge badge-active">active</span>`
		}
		email := userEmails[sess.UserID]
		if email == "" {
			email = fmt.Sprintf("user#%d", sess.UserID)
		}
		desc := sess.Description
		if desc == "" {
			desc = `<span style="color:#555">—</span>`
		}
		rows += fmt.Sprintf(`<tr>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td>%s</td>
<td><button class="btn btn-danger" onclick="deleteSession(%d, '%s')">Delete</button></td>
</tr>`, sess.TmuxName, email, desc, statusBadge, sess.CreatedAt.Format("2006-01-02 15:04"), sess.ID, sess.TmuxName)
	}
	if rows == "" {
		rows = `<tr><td colspan="6" style="text-align:center;color:#555;padding:32px;">No sessions yet.</td></tr>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ethsy - Admin Sessions</title>
<style>%s</style>
</head>
<body>
%s
<div class="container">
<h1>Sessions</h1>
<div class="card">
<table>
<thead><tr><th>Tmux Name</th><th>User</th><th>Description</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
<tbody>%s</tbody>
</table>
</div>
</div>
<script>
function deleteSession(id, name) {
  if (!confirm('Delete session ' + name + '?\nThis will kill the tmux session.')) return;
  fetch('/admin/sessions/' + id, {method: 'DELETE'})
    .then(function(r){ return r.json(); }).then(function(d){
      if (d.status === 'deleted') { location.reload(); }
      else { alert('Error: ' + JSON.stringify(d)); }
    }).catch(function(e){ alert('Request failed: ' + e); });
}
</script>
</body>
</html>`, adminSharedCSS, adminNav("/admin/sessions"), rows)
}

// handleAdminSessionByID handles DELETE /admin/sessions/:id
func (s *Server) handleAdminSessionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/admin/sessions/")
	sessionID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	sess, err := s.db.GetSessionByID(sessionID)
	if err != nil {
		log.Printf("[web] failed to get session: %v", err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if sess == nil {
		jsonError(w, http.StatusNotFound, "session not found")
		return
	}

	if err := s.sessMgr.Delete(sessionID); err != nil {
		log.Printf("[web] failed to delete session %d: %v", sessionID, err)
		jsonError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	log.Printf("[admin] deleted session: %s (id=%d)", sess.TmuxName, sessionID)

	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// extractDeviceName tries to extract the device/comment from an SSH public key.
// SSH keys often have a comment at the end: ssh-ed25519 AAAA... user@hostname
func extractDeviceName(publicKey string) string {
	parts := strings.Fields(publicKey)
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}
