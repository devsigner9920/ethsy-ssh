// Package web provides the HTTP server for ethsy-server.
// Designed to run behind a reverse proxy (Caddy) that handles TLS termination.
package web

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/devsigner9920/ethsy-ssh/server/auth"
	"github.com/devsigner9920/ethsy-ssh/server/config"
	"github.com/devsigner9920/ethsy-ssh/server/db"
	"github.com/devsigner9920/ethsy-ssh/server/session"
	"github.com/devsigner9920/ethsy-ssh/server/sshkey"
)

// Server is the main web server.
type Server struct {
	cfg     *config.Config
	db      *db.DB
	auth    *auth.Manager
	sshMgr  *sshkey.Manager
	sessMgr *session.Manager
	mux     *http.ServeMux
}

// NewServer creates a new web server with all dependencies.
func NewServer(cfg *config.Config, database *db.DB, authMgr *auth.Manager, sshMgr *sshkey.Manager, sessMgr *session.Manager) *Server {
	s := &Server{
		cfg:     cfg,
		db:      database,
		auth:    authMgr,
		sshMgr:  sshMgr,
		sessMgr: sessMgr,
		mux:     http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// registerRoutes sets up all HTTP routes.
func (s *Server) registerRoutes() {
	// Auth endpoints (connect domain).
	s.mux.HandleFunc("/auth", s.handleAuth)
	s.mux.HandleFunc("/auth/callback", s.handleAuthCallback)
	s.mux.HandleFunc("/api/auth/poll", s.handleAuthPoll)

	// API endpoints (connect domain, JWT required).
	s.mux.HandleFunc("/api/me", s.handleMe)
	s.mux.HandleFunc("/api/register", s.handleRegister)
	s.mux.HandleFunc("/api/register-key", s.handleRegisterKey)
	s.mux.HandleFunc("/api/revoke-key", s.handleRevokeKey)
	s.mux.HandleFunc("/api/sessions", s.handleSessions)
	s.mux.HandleFunc("/api/sessions/", s.handleSessionByID)

	// Admin endpoints (localhost only).
	s.mux.HandleFunc("/admin", s.requireLocalhost(s.handleAdmin))
	s.mux.HandleFunc("/admin/users", s.requireLocalhost(s.handleAdminUsers))
	s.mux.HandleFunc("/admin/users/", s.requireLocalhost(s.handleAdminUserByID))
	s.mux.HandleFunc("/admin/sessions", s.requireLocalhost(s.handleAdminSessions))
	s.mux.HandleFunc("/admin/sessions/", s.requireLocalhost(s.handleAdminSessionByID))

	// Health check.
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Root page.
	s.mux.HandleFunc("/", s.handleRoot)
}

// ServeHTTP dispatches requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// handleRoot serves the landing page for "/" and a 404 page for unknown paths.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ethsy - Not Found</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.container { text-align: center; }
.code { font-size: 120px; font-weight: 700; color: #333; line-height: 1; }
.message { font-size: 18px; color: #666; margin-top: 12px; }
a { color: #888; text-decoration: none; margin-top: 24px; display: inline-block; border: 1px solid #333; padding: 8px 20px; border-radius: 6px; transition: all 0.2s; }
a:hover { color: #fff; border-color: #555; }
</style></head><body>
<div class="container">
<div class="code">404</div>
<div class="message">Page not found</div>
<a href="/">Back to home</a>
</div>
</body></html>`)
		return
	}

	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ethsy.me</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e0e0e0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.container { text-align: center; }
.logo { font-size: 48px; font-weight: 700; letter-spacing: -1px; }
.logo span { color: #4a9eff; }
.tagline { font-size: 16px; color: #666; margin-top: 8px; }
.terminal { margin-top: 32px; background: #111; border: 1px solid #222; border-radius: 8px; padding: 20px 28px; text-align: left; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 14px; }
.prompt { color: #4a9eff; }
.cmd { color: #ccc; }
.comment { color: #555; }
</style></head><body>
<div class="container">
<div class="logo">ethsy<span>.me</span></div>
<div class="tagline">Remote tmux session sharing</div>
<div class="terminal">
<div><span class="comment"># Install</span></div>
<div><span class="prompt">$ </span><span class="cmd">brew tap devsigner9920/tap && brew install ethsy-connect</span></div>
<div style="margin-top: 12px"><span class="comment"># Connect</span></div>
<div><span class="prompt">$ </span><span class="cmd">ethsy</span></div>
</div>
</div>
</body></html>`)
}

// Start starts the HTTP server on the configured listen address.
// TLS is handled by the reverse proxy (Caddy).
func (s *Server) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on context cancellation.
	go func() {
		<-ctx.Done()
		log.Println("[web] shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("[web] starting HTTP server on %s (behind reverse proxy)", s.cfg.Listen)
	log.Printf("[web] connect domain: %s, ssh domain: %s", s.cfg.ConnectDomain, s.cfg.SSHDomain)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server error: %w", err)
	}
	return nil
}
