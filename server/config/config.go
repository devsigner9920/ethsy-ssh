// Package config handles loading and managing server configuration from YAML.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level server configuration.
type Config struct {
	ConnectDomain string        `yaml:"connect_domain"`
	SSHDomain     string        `yaml:"ssh_domain"`
	ReverseProxy  bool          `yaml:"reverse_proxy"`
	Listen        string        `yaml:"listen"`
	OAuth         OAuthConfig   `yaml:"oauth"`
	JWT           JWTConfig     `yaml:"jwt"`
	SSH           SSHConfig     `yaml:"ssh"`
	Session       SessionConfig `yaml:"session"`
	Admin         AdminConfig   `yaml:"admin"`
}

// OAuthConfig holds Google OAuth2 credentials.
type OAuthConfig struct {
	Provider     string `yaml:"provider"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// JWTConfig holds JWT signing configuration.
type JWTConfig struct {
	Secret string        `yaml:"secret"`
	Expiry time.Duration `yaml:"expiry"`
}

// SSHConfig holds SSH-related settings.
type SSHConfig struct {
	Port           int    `yaml:"port"`
	AuthorizedKeys string `yaml:"authorized_keys"`
	MaxKeysPerUser int    `yaml:"max_keys_per_user"`
}

// SessionConfig holds tmux session management settings.
type SessionConfig struct {
	CleanupAfter time.Duration `yaml:"cleanup_after"`
	TmuxConfig   string        `yaml:"tmux_config"`
}

// AdminConfig holds admin panel settings.
type AdminConfig struct {
	Emails []string `yaml:"emails"`
}

// DefaultConfigDir returns the default configuration directory path.
func DefaultConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".ethsy", "server")
	}
	return filepath.Join(home, ".ethsy", "server")
}

// DefaultConfigPath returns the default config file path.
func DefaultConfigPath() string {
	return filepath.Join(DefaultConfigDir(), "config.yaml")
}

// Load reads and parses the configuration file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	cfg.setDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Expand ~ in paths.
	cfg.SSH.AuthorizedKeys = expandHome(cfg.SSH.AuthorizedKeys)
	cfg.Session.TmuxConfig = expandHome(cfg.Session.TmuxConfig)

	return cfg, nil
}

// setDefaults fills in any missing configuration values with sensible defaults.
func (c *Config) setDefaults() {
	if c.ConnectDomain == "" {
		c.ConnectDomain = "connect.ethsy.me"
	}
	if c.SSHDomain == "" {
		c.SSHDomain = "ssh.ethsy.me"
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:10001"
	}
	if c.OAuth.Provider == "" {
		c.OAuth.Provider = "google"
	}
	if c.JWT.Expiry == 0 {
		c.JWT.Expiry = 720 * time.Hour // 30 days
	}
	if c.SSH.Port == 0 {
		c.SSH.Port = 9920
	}
	if c.SSH.AuthorizedKeys == "" {
		c.SSH.AuthorizedKeys = "~/.ssh/authorized_keys"
	}
	if c.SSH.MaxKeysPerUser == 0 {
		c.SSH.MaxKeysPerUser = 5
	}
	if c.Session.CleanupAfter == 0 {
		c.Session.CleanupAfter = 168 * time.Hour // 7 days
	}
	if c.Session.TmuxConfig == "" {
		c.Session.TmuxConfig = "~/.ethsy/server/tmux.conf"
	}
}

// validate checks that required fields are present.
func (c *Config) validate() error {
	if c.OAuth.ClientID == "" {
		return fmt.Errorf("oauth.client_id is required")
	}
	if c.OAuth.ClientSecret == "" {
		return fmt.Errorf("oauth.client_secret is required")
	}
	if c.JWT.Secret == "" {
		return fmt.Errorf("jwt.secret is required")
	}
	return nil
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if len(path) == 0 {
		return path
	}
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[1:])
	}
	return path
}

// GenerateDefault creates a default config file at the given path, prompting
// for required values via the provided reader function.
func GenerateDefault(path string, clientID, clientSecret, jwtSecret, adminEmail string) error {
	cfg := Config{
		ConnectDomain: "connect.ethsy.me",
		SSHDomain:     "ssh.ethsy.me",
		ReverseProxy:  true,
		Listen:        "127.0.0.1:10001",
		OAuth: OAuthConfig{
			Provider:     "google",
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
		JWT: JWTConfig{
			Secret: jwtSecret,
			Expiry: 720 * time.Hour,
		},
		SSH: SSHConfig{
			Port:           9920,
			AuthorizedKeys: "~/.ssh/authorized_keys",
			MaxKeysPerUser: 5,
		},
		Session: SessionConfig{
			CleanupAfter: 168 * time.Hour,
			TmuxConfig:   "~/.ethsy/server/tmux.conf",
		},
		Admin: AdminConfig{
			Emails: []string{adminEmail},
		},
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}
