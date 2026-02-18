// ethsy-server is the host server for the ethsy-ssh remote tmux session sharing
// platform. It provides OAuth authentication, SSH key management, tmux session
// lifecycle management, and an admin panel.
//
// Usage:
//
//	ethsy-server init            # Interactive setup
//	ethsy-server start           # Start the server
//	ethsy-server install-service # Install as macOS launchd service
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/devsigner9920/ethsy-ssh/server/auth"
	"github.com/devsigner9920/ethsy-ssh/server/config"
	"github.com/devsigner9920/ethsy-ssh/server/db"
	"github.com/devsigner9920/ethsy-ssh/server/session"
	"github.com/devsigner9920/ethsy-ssh/server/sshkey"
	"github.com/devsigner9920/ethsy-ssh/server/web"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		if err := runInit(); err != nil {
			log.Fatalf("init failed: %v", err)
		}
	case "start":
		if err := runStart(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	case "install-service":
		if err := runInstallService(); err != nil {
			log.Fatalf("install-service failed: %v", err)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("ethsy-server - Remote tmux session sharing server")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  ethsy-server init            Interactive setup (create config)")
	fmt.Println("  ethsy-server start           Start the server")
	fmt.Println("  ethsy-server install-service Install as macOS launchd service")
	fmt.Println("  ethsy-server help            Show this help")
}

// runInit performs interactive setup, creating the config file.
func runInit() error {
	configPath := config.DefaultConfigPath()

	// Check if config already exists.
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config file already exists at %s\n", configPath)
		fmt.Print("Overwrite? (y/N): ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== ethsy-server Initial Setup ===")
	fmt.Println()

	// Google OAuth credentials.
	fmt.Print("Google OAuth Client ID: ")
	clientID, _ := reader.ReadString('\n')
	clientID = strings.TrimSpace(clientID)

	fmt.Print("Google OAuth Client Secret: ")
	clientSecret, _ := reader.ReadString('\n')
	clientSecret = strings.TrimSpace(clientSecret)

	// Admin email.
	fmt.Print("Admin email address: ")
	adminEmail, _ := reader.ReadString('\n')
	adminEmail = strings.TrimSpace(adminEmail)

	// Generate JWT secret.
	jwtSecret, err := generateSecret(32)
	if err != nil {
		return fmt.Errorf("generate JWT secret: %w", err)
	}

	// Create config file.
	if err := config.GenerateDefault(configPath, clientID, clientSecret, jwtSecret, adminEmail); err != nil {
		return err
	}

	fmt.Printf("\nConfig written to %s\n", configPath)
	fmt.Println("You can now start the server with: ethsy-server start")

	// Create tmux config.
	tmuxConfPath := filepath.Join(config.DefaultConfigDir(), "tmux.conf")
	if err := createDefaultTmuxConfig(tmuxConfPath); err != nil {
		log.Printf("Warning: failed to create tmux config: %v", err)
	} else {
		fmt.Printf("Tmux config written to %s\n", tmuxConfPath)
	}

	return nil
}

// runStart loads config and starts the server.
func runStart() error {
	configPath := config.DefaultConfigPath()

	// Load configuration.
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config from %s: %w", configPath, err)
	}

	log.Printf("[main] config loaded from %s", configPath)

	// Open database.
	dbPath := filepath.Join(config.DefaultConfigDir(), "ethsy.db")
	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	log.Printf("[main] database opened at %s", dbPath)

	// Create auth manager.
	redirectURL := fmt.Sprintf("https://%s/auth/callback", cfg.ConnectDomain)
	authMgr := auth.NewManager(
		cfg.JWT.Secret,
		cfg.JWT.Expiry,
		cfg.OAuth.ClientID,
		cfg.OAuth.ClientSecret,
		redirectURL,
		cfg.Admin.Emails,
	)

	// Create SSH key manager.
	sshMgr := sshkey.NewManager(cfg.SSH.AuthorizedKeys)

	// Create session manager.
	sessMgr := session.NewManager(database, cfg.Session.TmuxConfig, cfg.Session.CleanupAfter)

	// Create web server.
	srv := web.NewServer(cfg, database, authMgr, sshMgr, sessMgr)

	// Set up context with signal handling for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("[main] received signal: %v, shutting down...", sig)
		cancel()
	}()

	// Start background cleanup tasks.
	go runCleanupLoop(ctx, database, sshMgr, sessMgr, authMgr)

	// Start the web server (blocks until shutdown).
	return srv.Start(ctx)
}

// runCleanupLoop periodically cleans up expired keys, inactive sessions, and
// expired auth sessions.
func runCleanupLoop(ctx context.Context, database *db.DB, sshMgr *sshkey.Manager, sessMgr *session.Manager, authMgr *auth.Manager) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("[cleanup] running periodic cleanup...")

			// Clean up expired SSH keys.
			expiredKeys, err := database.DeleteExpiredSSHKeys()
			if err != nil {
				log.Printf("[cleanup] failed to delete expired SSH keys: %v", err)
			} else if len(expiredKeys) > 0 {
				keyIDs := make([]int64, len(expiredKeys))
				for i, k := range expiredKeys {
					keyIDs[i] = k.ID
				}
				if err := sshMgr.CleanupKeys(keyIDs); err != nil {
					log.Printf("[cleanup] failed to cleanup authorized_keys: %v", err)
				}
				log.Printf("[cleanup] removed %d expired SSH keys", len(expiredKeys))
			}

			// Clean up inactive sessions.
			if err := sessMgr.CleanupInactive(); err != nil {
				log.Printf("[cleanup] failed to cleanup inactive sessions: %v", err)
			}

			// Clean up expired auth sessions.
			if err := database.CleanupExpiredAuthSessions(); err != nil {
				log.Printf("[cleanup] failed to cleanup expired auth sessions: %v", err)
			}

			// Clean up expired OAuth states.
			authMgr.CleanupExpiredStates()
		}
	}
}

// runInstallService creates a macOS launchd plist for auto-starting the server.
func runInstallService() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	// Find the server binary path.
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	plistDir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}

	plistPath := filepath.Join(plistDir, "me.ethsy.server.plist")
	logPath := filepath.Join(home, ".ethsy", "server", "ethsy-server.log")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>me.ethsy.server</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>start</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
	<key>WorkingDirectory</key>
	<string>%s</string>
</dict>
</plist>
`, execPath, logPath, logPath, home)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	fmt.Printf("LaunchAgent plist written to %s\n", plistPath)
	fmt.Println()
	fmt.Println("To load the service:")
	fmt.Printf("  launchctl load %s\n", plistPath)
	fmt.Println()
	fmt.Println("To unload the service:")
	fmt.Printf("  launchctl unload %s\n", plistPath)
	fmt.Println()
	fmt.Println("The server will automatically start on login and restart on crash.")

	return nil
}

// generateSecret generates a cryptographically random hex string.
func generateSecret(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// createDefaultTmuxConfig writes a sensible default tmux configuration.
func createDefaultTmuxConfig(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmuxConf := `# ethsy-server tmux configuration
# This config is applied to all ethsy tmux sessions.

# Use 256 colors.
set -g default-terminal "screen-256color"
set -ga terminal-overrides ",*256col*:Tc"

# Enable mouse support.
set -g mouse on

# Set scrollback buffer size.
set -g history-limit 10000

# Start windows and panes at 1, not 0.
set -g base-index 1
setw -g pane-base-index 1

# Renumber windows when a window is closed.
set -g renumber-windows on

# Status bar.
set -g status-style "bg=#333333 fg=#ffffff"
set -g status-left " #S "
set -g status-right " %H:%M "
set -g status-left-length 20

# Window status.
setw -g window-status-format " #I:#W "
setw -g window-status-current-format " #I:#W "
setw -g window-status-current-style "bg=#555555 fg=#ffffff bold"

# Pane borders.
set -g pane-border-style "fg=#444444"
set -g pane-active-border-style "fg=#888888"

# Reduce escape time for faster key response.
set -sg escape-time 10

# Activity monitoring.
setw -g monitor-activity on
set -g visual-activity off
`

	return os.WriteFile(path, []byte(tmuxConf), 0644)
}
