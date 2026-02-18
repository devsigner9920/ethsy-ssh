// Package db provides SQLite database initialization and query helpers
// for the ethsy-server application.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a sql.DB connection with ethsy-specific query methods.
type DB struct {
	conn *sql.DB
}

// User represents a registered user.
type User struct {
	ID        int64
	Email     string
	Username  string
	IsAdmin   bool
	CreatedAt time.Time
}

// SSHKey represents a registered SSH public key for a device.
type SSHKey struct {
	ID          int64
	UserID      int64
	PublicKey   string
	Fingerprint string
	DeviceName  string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Session represents a tmux session record.
type Session struct {
	ID           int64
	UserID       int64
	TmuxName     string
	Description  string
	CreatedAt    time.Time
	LastAttached time.Time
}

// AuthSession represents a CLI polling auth session.
type AuthSession struct {
	SessionID string
	Token     sql.NullString
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Open opens or creates the SQLite database at the given path.
func Open(dbPath string) (*DB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Set connection pool limits for SQLite.
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	return db, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// Conn returns the underlying sql.DB connection for advanced queries.
func (d *DB) Conn() *sql.DB {
	return d.conn
}

// migrate creates the database schema if it does not exist.
func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		username TEXT UNIQUE NOT NULL,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS ssh_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		public_key TEXT NOT NULL,
		fingerprint TEXT UNIQUE NOT NULL,
		device_name TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		tmux_name TEXT UNIQUE NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		last_attached DATETIME NOT NULL DEFAULT (datetime('now')),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS auth_sessions (
		session_id TEXT PRIMARY KEY,
		token TEXT,
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		expires_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_ssh_keys_user_id ON ssh_keys(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_ssh_keys_expires_at ON ssh_keys(expires_at);
	CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at);
	`

	_, err := d.conn.Exec(schema)
	return err
}

// --- User Queries ---

// CreateUser inserts a new user and returns the user ID.
func (d *DB) CreateUser(email, username string, isAdmin bool) (int64, error) {
	result, err := d.conn.Exec(
		"INSERT INTO users (email, username, is_admin) VALUES (?, ?, ?)",
		email, username, isAdmin,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetUserByEmail retrieves a user by email. Returns nil if not found.
func (d *DB) GetUserByEmail(email string) (*User, error) {
	u := &User{}
	err := d.conn.QueryRow(
		"SELECT id, email, username, is_admin, created_at FROM users WHERE email = ?",
		email,
	).Scan(&u.ID, &u.Email, &u.Username, &u.IsAdmin, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByID retrieves a user by ID.
func (d *DB) GetUserByID(id int64) (*User, error) {
	u := &User{}
	err := d.conn.QueryRow(
		"SELECT id, email, username, is_admin, created_at FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Email, &u.Username, &u.IsAdmin, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByUsername retrieves a user by username. Returns nil if not found.
func (d *DB) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	err := d.conn.QueryRow(
		"SELECT id, email, username, is_admin, created_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Email, &u.Username, &u.IsAdmin, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// ListUsers returns all registered users.
func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.conn.Query("SELECT id, email, username, is_admin, created_at FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Username, &u.IsAdmin, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// DeleteUser removes a user by ID. Cascading deletes handle ssh_keys and sessions.
func (d *DB) DeleteUser(id int64) error {
	_, err := d.conn.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// --- SSH Key Queries ---

// CreateSSHKey inserts a new SSH key record and returns the key ID.
func (d *DB) CreateSSHKey(userID int64, publicKey, fingerprint, deviceName string, expiresAt time.Time) (int64, error) {
	result, err := d.conn.Exec(
		"INSERT INTO ssh_keys (user_id, public_key, fingerprint, device_name, expires_at) VALUES (?, ?, ?, ?, ?)",
		userID, publicKey, fingerprint, deviceName, expiresAt,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetSSHKeysByUserID returns all SSH keys for a user.
func (d *DB) GetSSHKeysByUserID(userID int64) ([]SSHKey, error) {
	rows, err := d.conn.Query(
		"SELECT id, user_id, public_key, fingerprint, device_name, created_at, expires_at FROM ssh_keys WHERE user_id = ? ORDER BY id",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []SSHKey
	for rows.Next() {
		var k SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.PublicKey, &k.Fingerprint, &k.DeviceName, &k.CreatedAt, &k.ExpiresAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// CountSSHKeysByUserID returns the number of SSH keys for a user.
func (d *DB) CountSSHKeysByUserID(userID int64) (int, error) {
	var count int
	err := d.conn.QueryRow("SELECT COUNT(*) FROM ssh_keys WHERE user_id = ?", userID).Scan(&count)
	return count, err
}

// GetSSHKeyByFingerprint returns an SSH key by fingerprint. Returns nil if not found.
func (d *DB) GetSSHKeyByFingerprint(fingerprint string) (*SSHKey, error) {
	k := &SSHKey{}
	err := d.conn.QueryRow(
		"SELECT id, user_id, public_key, fingerprint, device_name, created_at, expires_at FROM ssh_keys WHERE fingerprint = ?",
		fingerprint,
	).Scan(&k.ID, &k.UserID, &k.PublicKey, &k.Fingerprint, &k.DeviceName, &k.CreatedAt, &k.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

// DeleteSSHKey removes an SSH key by ID.
func (d *DB) DeleteSSHKey(id int64) error {
	_, err := d.conn.Exec("DELETE FROM ssh_keys WHERE id = ?", id)
	return err
}

// DeleteSSHKeysByUserID removes all SSH keys for a user.
func (d *DB) DeleteSSHKeysByUserID(userID int64) error {
	_, err := d.conn.Exec("DELETE FROM ssh_keys WHERE user_id = ?", userID)
	return err
}

// DeleteExpiredSSHKeys removes all SSH keys past their expiration date and
// returns the deleted key records (for authorized_keys cleanup).
func (d *DB) DeleteExpiredSSHKeys() ([]SSHKey, error) {
	rows, err := d.conn.Query(
		"SELECT id, user_id, public_key, fingerprint, device_name, created_at, expires_at FROM ssh_keys WHERE expires_at < datetime('now')",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var expired []SSHKey
	for rows.Next() {
		var k SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.PublicKey, &k.Fingerprint, &k.DeviceName, &k.CreatedAt, &k.ExpiresAt); err != nil {
			return nil, err
		}
		expired = append(expired, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	_, err = d.conn.Exec("DELETE FROM ssh_keys WHERE expires_at < datetime('now')")
	if err != nil {
		return nil, err
	}
	return expired, nil
}

// --- Session Queries ---

// CreateSession inserts a new tmux session record and returns the session ID.
func (d *DB) CreateSession(userID int64, tmuxName, description string) (int64, error) {
	result, err := d.conn.Exec(
		"INSERT INTO sessions (user_id, tmux_name, description) VALUES (?, ?, ?)",
		userID, tmuxName, description,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetSessionsByUserID returns all sessions for a user.
func (d *DB) GetSessionsByUserID(userID int64) ([]Session, error) {
	rows, err := d.conn.Query(
		"SELECT id, user_id, tmux_name, description, created_at, last_attached FROM sessions WHERE user_id = ? ORDER BY id",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TmuxName, &s.Description, &s.CreatedAt, &s.LastAttached); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// GetSessionByID returns a session by ID.
func (d *DB) GetSessionByID(id int64) (*Session, error) {
	s := &Session{}
	err := d.conn.QueryRow(
		"SELECT id, user_id, tmux_name, description, created_at, last_attached FROM sessions WHERE id = ?",
		id,
	).Scan(&s.ID, &s.UserID, &s.TmuxName, &s.Description, &s.CreatedAt, &s.LastAttached)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ListAllSessions returns all sessions across all users (for admin).
func (d *DB) ListAllSessions() ([]Session, error) {
	rows, err := d.conn.Query(
		"SELECT s.id, s.user_id, s.tmux_name, s.description, s.created_at, s.last_attached FROM sessions s ORDER BY s.id",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TmuxName, &s.Description, &s.CreatedAt, &s.LastAttached); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// NextSessionNumber returns the next available session number for a user.
func (d *DB) NextSessionNumber(userID int64) (int, error) {
	var maxNum sql.NullInt64
	// Extract the session number from tmux_name pattern ethsy_{user_id}_{n}.
	err := d.conn.QueryRow(
		"SELECT MAX(CAST(SUBSTR(tmux_name, LENGTH(?) + 1) AS INTEGER)) FROM sessions WHERE tmux_name LIKE ?",
		fmt.Sprintf("ethsy_%d_", userID),
		fmt.Sprintf("ethsy_%d_%%", userID),
	).Scan(&maxNum)
	if err != nil {
		return 1, err
	}
	if !maxNum.Valid {
		return 1, nil
	}
	return int(maxNum.Int64) + 1, nil
}

// DeleteSession removes a session by ID.
func (d *DB) DeleteSession(id int64) error {
	_, err := d.conn.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

// DeleteSessionsByUserID removes all sessions for a user.
func (d *DB) DeleteSessionsByUserID(userID int64) error {
	_, err := d.conn.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}

// UpdateSessionLastAttached updates the last_attached timestamp for a session.
func (d *DB) UpdateSessionLastAttached(id int64) error {
	_, err := d.conn.Exec("UPDATE sessions SET last_attached = datetime('now') WHERE id = ?", id)
	return err
}

// GetInactiveSessions returns sessions not attached within the given duration.
func (d *DB) GetInactiveSessions(threshold time.Duration) ([]Session, error) {
	cutoff := time.Now().Add(-threshold)
	rows, err := d.conn.Query(
		"SELECT id, user_id, tmux_name, description, created_at, last_attached FROM sessions WHERE last_attached < ?",
		cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TmuxName, &s.Description, &s.CreatedAt, &s.LastAttached); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// --- Auth Session Queries ---

// CreateAuthSession inserts a new polling auth session (token is NULL until authenticated).
func (d *DB) CreateAuthSession(sessionID string, expiresAt time.Time) error {
	_, err := d.conn.Exec(
		"INSERT OR REPLACE INTO auth_sessions (session_id, token, expires_at) VALUES (?, NULL, ?)",
		sessionID, expiresAt,
	)
	return err
}

// SetAuthSessionToken sets the JWT token on a completed auth session.
func (d *DB) SetAuthSessionToken(sessionID, token string) error {
	result, err := d.conn.Exec(
		"UPDATE auth_sessions SET token = ? WHERE session_id = ? AND expires_at > datetime('now')",
		token, sessionID,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("auth session not found or expired: %s", sessionID)
	}
	return nil
}

// ConsumeAuthSession retrieves and deletes the auth session (one-time use).
// Returns the token if authentication is complete, empty string if still pending.
func (d *DB) ConsumeAuthSession(sessionID string) (string, error) {
	var as AuthSession
	err := d.conn.QueryRow(
		"SELECT session_id, token, created_at, expires_at FROM auth_sessions WHERE session_id = ? AND expires_at > datetime('now')",
		sessionID,
	).Scan(&as.SessionID, &as.Token, &as.CreatedAt, &as.ExpiresAt)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("auth session not found or expired")
	}
	if err != nil {
		return "", err
	}

	// If token is set, consume (delete) the session.
	if as.Token.Valid && as.Token.String != "" {
		_, _ = d.conn.Exec("DELETE FROM auth_sessions WHERE session_id = ?", sessionID)
		return as.Token.String, nil
	}

	// Token not yet set, still pending.
	return "", nil
}

// CleanupExpiredAuthSessions removes expired auth sessions.
func (d *DB) CleanupExpiredAuthSessions() error {
	_, err := d.conn.Exec("DELETE FROM auth_sessions WHERE expires_at < datetime('now')")
	return err
}
