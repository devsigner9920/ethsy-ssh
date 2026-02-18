// Package sshkey manages the ~/.ssh/authorized_keys file for ethsy-managed
// SSH public keys. It reads and writes keys tagged with ethsy-managed comments,
// leaving manually added keys untouched.
package sshkey

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// TagPrefix is the comment prefix used to identify ethsy-managed keys.
	TagPrefix = "# ethsy-managed:"
)

// Manager handles authorized_keys file operations.
type Manager struct {
	mu             sync.Mutex
	authorizedKeys string
}

// NewManager creates a new SSH key manager.
func NewManager(authorizedKeysPath string) *Manager {
	return &Manager{
		authorizedKeys: authorizedKeysPath,
	}
}

// AddKey adds a public key to authorized_keys with ethsy-managed tag.
// Format:
//
//	# ethsy-managed:{userID}:{keyID}
//	ssh-ed25519 AAAA... user@device
func (m *Manager) AddKey(userID, keyID int64, publicKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure the directory exists.
	dir := filepath.Dir(m.authorizedKeys)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create .ssh directory: %w", err)
	}

	lines, err := m.readLines()
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read authorized_keys: %w", err)
	}

	// Append the new key with tag.
	tag := fmt.Sprintf("%s%d:%d", TagPrefix, userID, keyID)
	lines = append(lines, tag, strings.TrimSpace(publicKey))

	return m.writeLines(lines)
}

// RemoveKey removes a specific key identified by keyID from authorized_keys.
func (m *Manager) RemoveKey(keyID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to remove.
		}
		return fmt.Errorf("read authorized_keys: %w", err)
	}

	filtered := m.filterOutKey(lines, func(tag string) bool {
		return strings.HasSuffix(tag, fmt.Sprintf(":%d", keyID))
	})

	return m.writeLines(filtered)
}

// RemoveAllKeysForUser removes all keys for a given user from authorized_keys.
func (m *Manager) RemoveAllKeysForUser(userID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read authorized_keys: %w", err)
	}

	prefix := fmt.Sprintf("%s%d:", TagPrefix, userID)
	filtered := m.filterOutKey(lines, func(tag string) bool {
		return strings.HasPrefix(tag, prefix)
	})

	return m.writeLines(filtered)
}

// RemoveKeyByID removes a key by its exact user_id:key_id combination.
func (m *Manager) RemoveKeyByID(userID, keyID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read authorized_keys: %w", err)
	}

	target := fmt.Sprintf("%s%d:%d", TagPrefix, userID, keyID)
	filtered := m.filterOutKey(lines, func(tag string) bool {
		return tag == target
	})

	return m.writeLines(filtered)
}

// CleanupKeys removes specific keys by their keyIDs from authorized_keys.
// Used for batch cleanup of expired keys.
func (m *Manager) CleanupKeys(keyIDs []int64) error {
	if len(keyIDs) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	lines, err := m.readLines()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read authorized_keys: %w", err)
	}

	idSet := make(map[int64]bool, len(keyIDs))
	for _, id := range keyIDs {
		idSet[id] = true
	}

	filtered := m.filterOutKey(lines, func(tag string) bool {
		// Parse the key_id from the tag.
		parts := strings.Split(strings.TrimPrefix(tag, TagPrefix), ":")
		if len(parts) != 2 {
			return false
		}
		var kid int64
		if _, err := fmt.Sscanf(parts[1], "%d", &kid); err != nil {
			return false
		}
		return idSet[kid]
	})

	if len(filtered) != len(lines) {
		log.Printf("[sshkey] cleaned up %d expired keys from authorized_keys", (len(lines)-len(filtered))/2)
	}

	return m.writeLines(filtered)
}

// filterOutKey removes ethsy-managed key blocks where the tag matches the predicate.
// Each key block is a comment line followed by the key line.
func (m *Manager) filterOutKey(lines []string, matchTag func(string) bool) []string {
	var filtered []string
	skip := false
	for _, line := range lines {
		if strings.HasPrefix(line, TagPrefix) {
			if matchTag(line) {
				skip = true // Skip this tag line and the following key line.
				continue
			}
		}
		if skip {
			skip = false // Skip the key line after a matched tag.
			continue
		}
		filtered = append(filtered, line)
	}
	return filtered
}

// readLines reads the authorized_keys file and returns its lines.
func (m *Manager) readLines() ([]string, error) {
	data, err := os.ReadFile(m.authorizedKeys)
	if err != nil {
		return nil, err
	}

	content := strings.TrimRight(string(data), "\n")
	if content == "" {
		return nil, nil
	}
	return strings.Split(content, "\n"), nil
}

// writeLines writes lines back to the authorized_keys file.
func (m *Manager) writeLines(lines []string) error {
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(m.authorizedKeys, []byte(content), 0600)
}
