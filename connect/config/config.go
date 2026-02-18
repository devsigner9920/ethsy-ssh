package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultServer = "connect.ethsy.me"
	configDir     = ".ethsy/connect"
	configFile    = "config.json"
)

// Config holds the client authentication state.
type Config struct {
	Token    string `json:"token"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Server   string `json:"server"`
}

// ConfigDir returns the absolute path to ~/.ethsy/connect.
func ConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, configDir)
}

// ConfigPath returns the absolute path to config.json.
func ConfigPath() string {
	return filepath.Join(ConfigDir(), configFile)
}

// KeyDir returns the absolute path to ~/.ethsy/connect/key.
func KeyDir() string {
	return filepath.Join(ConfigDir(), "key")
}

// PrivateKeyPath returns the path to the private key file.
func PrivateKeyPath() string {
	return filepath.Join(KeyDir(), "id_ed25519")
}

// PublicKeyPath returns the path to the public key file.
func PublicKeyPath() string {
	return filepath.Join(KeyDir(), "id_ed25519.pub")
}

// Load reads the config from disk. Returns a default config if the file
// does not exist.
func Load() (*Config, error) {
	cfg := &Config{
		Server: DefaultServer,
	}

	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Server == "" {
		cfg.Server = DefaultServer
	}

	return cfg, nil
}

// Save writes the config to disk, creating directories as needed.
func (c *Config) Save() error {
	dir := ConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(), data, 0600)
}

// IsAuthenticated returns true if a token exists and has not expired.
func (c *Config) IsAuthenticated() bool {
	if c.Token == "" {
		return false
	}
	return !c.IsTokenExpired()
}

// IsTokenExpired checks whether the JWT token has expired by decoding the
// payload and reading the "exp" claim. Returns true if the token is expired
// or cannot be parsed.
func (c *Config) IsTokenExpired() bool {
	if c.Token == "" {
		return true
	}

	exp, err := extractExpiry(c.Token)
	if err != nil {
		return true
	}

	return time.Now().After(exp)
}

// TokenExpiry returns the expiry time of the token, or the zero value on error.
func (c *Config) TokenExpiry() time.Time {
	if c.Token == "" {
		return time.Time{}
	}
	exp, err := extractExpiry(c.Token)
	if err != nil {
		return time.Time{}
	}
	return exp
}

// Delete removes the config file and the key directory.
func Delete() error {
	dir := ConfigDir()
	return os.RemoveAll(dir)
}

// extractExpiry decodes the JWT payload (without verification) and returns
// the expiration time.
func extractExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, errInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, err
	}

	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, err
	}

	if claims.Exp == 0 {
		return time.Time{}, errInvalidToken
	}

	return time.Unix(int64(claims.Exp), 0), nil
}

// ExtractEmail decodes the JWT payload and returns the email claim.
func ExtractEmail(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}

	return claims.Email, nil
}

var errInvalidToken = &tokenError{"invalid token"}

type tokenError struct {
	msg string
}

func (e *tokenError) Error() string {
	return e.msg
}
