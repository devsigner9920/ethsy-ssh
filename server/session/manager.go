// Package session manages tmux session lifecycle for the ethsy-server.
// Sessions are owned by users (email-based) and can be shared across devices.
package session

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/devsigner9920/ethsy-ssh/server/db"
)

// Manager handles tmux session creation, listing, and cleanup.
type Manager struct {
	database   *db.DB
	tmuxConfig string
	cleanup    time.Duration
}

// NewManager creates a new session manager.
func NewManager(database *db.DB, tmuxConfig string, cleanupAfter time.Duration) *Manager {
	return &Manager{
		database:   database,
		tmuxConfig: tmuxConfig,
		cleanup:    cleanupAfter,
	}
}

// Create creates a new tmux session for the given user. It assigns the next
// available session number and sets the working directory to ~/{username}.
func (m *Manager) Create(userID int64, username, description string) (*db.Session, error) {
	// Determine next session number.
	num, err := m.database.NextSessionNumber(userID)
	if err != nil {
		return nil, fmt.Errorf("get next session number: %w", err)
	}

	tmuxName := fmt.Sprintf("ethsy_%d_%d", userID, num)

	// Resolve the user's home directory.
	homeDir, err := resolveUserHome(username)
	if err != nil {
		return nil, fmt.Errorf("resolve home for %s: %w", username, err)
	}

	// Create the home directory if it doesn't exist.
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		return nil, fmt.Errorf("create home dir %s: %w", homeDir, err)
	}

	// Build tmux command.
	args := []string{"new-session", "-d", "-s", tmuxName, "-c", homeDir, "-x", "200", "-y", "50"}
	if m.tmuxConfig != "" {
		if _, err := os.Stat(m.tmuxConfig); err == nil {
			args = append([]string{"-f", m.tmuxConfig}, args...)
		}
	}

	cmd := exec.Command("tmux", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("create tmux session: %s: %w", strings.TrimSpace(string(output)), err)
	}

	// Record in database.
	sessionID, err := m.database.CreateSession(userID, tmuxName, description)
	if err != nil {
		// Try to clean up the tmux session on DB failure.
		_ = exec.Command("tmux", "kill-session", "-t", tmuxName).Run()
		return nil, fmt.Errorf("record session in db: %w", err)
	}

	log.Printf("[session] created session %s (id=%d) for user %d", tmuxName, sessionID, userID)

	return &db.Session{
		ID:          sessionID,
		UserID:      userID,
		TmuxName:    tmuxName,
		Description: description,
		CreatedAt:   time.Now(),
		LastAttached: time.Now(),
	}, nil
}

// List returns all sessions for the given user.
func (m *Manager) List(userID int64) ([]db.Session, error) {
	return m.database.GetSessionsByUserID(userID)
}

// IsAlive checks if a tmux session is currently running.
func (m *Manager) IsAlive(tmuxName string) bool {
	cmd := exec.Command("tmux", "has-session", "-t", tmuxName)
	return cmd.Run() == nil
}

// Delete kills a tmux session and removes it from the database.
func (m *Manager) Delete(sessionID int64) error {
	sess, err := m.database.GetSessionByID(sessionID)
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}
	if sess == nil {
		return fmt.Errorf("session not found: %d", sessionID)
	}

	// Kill the tmux session (ignore error if already dead).
	cmd := exec.Command("tmux", "kill-session", "-t", sess.TmuxName)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[session] warning: failed to kill tmux session %s: %s: %v",
			sess.TmuxName, strings.TrimSpace(string(output)), err)
	}

	// Remove from database.
	if err := m.database.DeleteSession(sessionID); err != nil {
		return fmt.Errorf("delete session from db: %w", err)
	}

	log.Printf("[session] deleted session %s (id=%d)", sess.TmuxName, sessionID)
	return nil
}

// DeleteAllForUser kills and removes all sessions for a user.
func (m *Manager) DeleteAllForUser(userID int64) error {
	sessions, err := m.database.GetSessionsByUserID(userID)
	if err != nil {
		return fmt.Errorf("list sessions for user %d: %w", userID, err)
	}

	for _, sess := range sessions {
		cmd := exec.Command("tmux", "kill-session", "-t", sess.TmuxName)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[session] warning: failed to kill tmux session %s: %s: %v",
				sess.TmuxName, strings.TrimSpace(string(output)), err)
		}
	}

	return m.database.DeleteSessionsByUserID(userID)
}

// CleanupInactive removes sessions that have been inactive longer than the
// configured cleanup duration.
func (m *Manager) CleanupInactive() error {
	sessions, err := m.database.GetInactiveSessions(m.cleanup)
	if err != nil {
		return fmt.Errorf("get inactive sessions: %w", err)
	}

	if len(sessions) == 0 {
		return nil
	}

	log.Printf("[session] cleaning up %d inactive sessions", len(sessions))

	for _, sess := range sessions {
		cmd := exec.Command("tmux", "kill-session", "-t", sess.TmuxName)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[session] warning: failed to kill inactive tmux session %s: %s: %v",
				sess.TmuxName, strings.TrimSpace(string(output)), err)
		}
		if err := m.database.DeleteSession(sess.ID); err != nil {
			log.Printf("[session] warning: failed to delete inactive session %d: %v", sess.ID, err)
		}
	}

	return nil
}

// EnsureUserHome creates the home directory ~/{username} if it doesn't exist.
func EnsureUserHome(username string) error {
	homeDir, err := resolveUserHome(username)
	if err != nil {
		return err
	}
	return os.MkdirAll(homeDir, 0755)
}

// resolveUserHome returns the absolute path for a user's home directory.
// The directory is located at ~/{username} relative to the system user's home.
func resolveUserHome(username string) (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user: %w", err)
	}
	return filepath.Join(u.HomeDir, username), nil
}
