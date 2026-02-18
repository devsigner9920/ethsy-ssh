package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// GenerateAndSave creates a new Ed25519 keypair and saves it to the
// given directory. Returns the public key in OpenSSH authorized_keys format.
func GenerateAndSave(keyDir string) (string, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", fmt.Errorf("키 디렉터리 생성 실패: %w", err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("키 생성 실패: %w", err)
	}

	// Save private key in PEM format
	privKeyPath := filepath.Join(keyDir, "id_ed25519")
	if err := savePrivateKey(privKeyPath, privKey); err != nil {
		return "", err
	}

	// Convert to SSH public key and marshal to authorized_keys format
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("SSH 공개키 변환 실패: %w", err)
	}

	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPubKey))
	// MarshalAuthorizedKey appends a newline; trim it for clean storage
	pubKeyStr = trimNewline(pubKeyStr)

	// Save public key
	pubKeyPath := filepath.Join(keyDir, "id_ed25519.pub")
	if err := os.WriteFile(pubKeyPath, []byte(pubKeyStr+"\n"), 0644); err != nil {
		return "", fmt.Errorf("공개키 저장 실패: %w", err)
	}

	return pubKeyStr, nil
}

// LoadPublicKey reads the existing public key from disk. Returns an empty
// string and nil error if the file does not exist.
func LoadPublicKey(keyDir string) (string, error) {
	pubKeyPath := filepath.Join(keyDir, "id_ed25519.pub")

	data, err := os.ReadFile(pubKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("공개키 읽기 실패: %w", err)
	}

	return trimNewline(string(data)), nil
}

// EnsureKeys loads the existing public key, or generates a new keypair if
// none exists. Returns the public key string.
func EnsureKeys(keyDir string) (string, error) {
	pubKey, err := LoadPublicKey(keyDir)
	if err != nil {
		return "", err
	}
	if pubKey != "" {
		return pubKey, nil
	}
	return GenerateAndSave(keyDir)
}

// savePrivateKey marshals the Ed25519 private key to PEM format and writes
// it to disk with restricted permissions.
func savePrivateKey(path string, key ed25519.PrivateKey) error {
	// ed25519 private key seed is the first 32 bytes
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: marshalED25519PrivateKey(key),
	}

	data := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("비밀키 저장 실패: %w", err)
	}

	return nil
}

// marshalED25519PrivateKey produces the OpenSSH private key format for
// Ed25519 keys. This matches the format produced by ssh-keygen.
func marshalED25519PrivateKey(key ed25519.PrivateKey) []byte {
	pubKey := key.Public().(ed25519.PublicKey)
	seed := key.Seed()

	// Generate random check bytes
	var check [4]byte
	rand.Read(check[:])

	// Build the OpenSSH private key format
	var b []byte

	// Auth magic
	b = append(b, []byte("openssh-key-v1\x00")...)

	// ciphername (none)
	b = appendString(b, "none")
	// kdfname (none)
	b = appendString(b, "none")
	// kdfoptions (empty)
	b = appendString(b, "")
	// number of keys
	b = appendU32(b, 1)

	// Public key section
	pubSection := marshalED25519PubKey(pubKey)
	b = appendBytes(b, pubSection)

	// Private key section
	var priv []byte
	// checkint (repeated)
	priv = appendU32(priv, uint32(check[0])<<24|uint32(check[1])<<16|uint32(check[2])<<8|uint32(check[3]))
	priv = appendU32(priv, uint32(check[0])<<24|uint32(check[1])<<16|uint32(check[2])<<8|uint32(check[3]))
	// key type
	priv = appendString(priv, "ssh-ed25519")
	// public key
	priv = appendBytes(priv, pubKey)
	// private key (seed + public concatenated, 64 bytes)
	combined := make([]byte, 0, len(seed)+len(pubKey))
	combined = append(combined, seed...)
	combined = append(combined, pubKey...)
	priv = appendBytes(priv, combined)
	// comment (empty)
	priv = appendString(priv, "")

	// Padding to block size (8 bytes for none cipher)
	for i := 0; len(priv)%8 != 0; i++ {
		priv = append(priv, byte(i+1))
	}

	b = appendBytes(b, priv)

	return b
}

func marshalED25519PubKey(pubKey ed25519.PublicKey) []byte {
	var b []byte
	b = appendString(b, "ssh-ed25519")
	b = appendBytes(b, pubKey)
	return b
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendString(b []byte, s string) []byte {
	return appendBytes(b, []byte(s))
}

func appendBytes(b []byte, data []byte) []byte {
	b = appendU32(b, uint32(len(data)))
	return append(b, data...)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
