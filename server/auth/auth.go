// Package auth provides JWT token generation/validation and Google OAuth2
// helpers for the ethsy-server authentication flow.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Claims represents the JWT claims for an authenticated user.
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// GoogleUserInfo represents the user info returned by Google's userinfo v2 API.
type GoogleUserInfo struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// OAuthState represents a stored OAuth state parameter for CSRF prevention.
type OAuthState struct {
	SessionID string
	ExpiresAt time.Time
}

// Manager handles JWT operations and OAuth2 configuration.
type Manager struct {
	jwtSecret []byte
	jwtExpiry time.Duration
	oauthCfg  *oauth2.Config

	// In-memory store for OAuth state parameters (CSRF prevention).
	mu     sync.Mutex
	states map[string]*OAuthState

	// Email whitelist.
	allowedEmails map[string]bool
}

// NewManager creates a new auth manager.
func NewManager(jwtSecret string, jwtExpiry time.Duration, clientID, clientSecret, redirectURL string, allowedEmails []string) *Manager {
	emailMap := make(map[string]bool, len(allowedEmails))
	for _, e := range allowedEmails {
		emailMap[e] = true
	}

	return &Manager{
		jwtSecret: []byte(jwtSecret),
		jwtExpiry: jwtExpiry,
		oauthCfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		states:        make(map[string]*OAuthState),
		allowedEmails: emailMap,
	}
}

// GenerateToken creates a new JWT token for the given email.
func (m *Manager) GenerateToken(email string) (string, error) {
	now := time.Now()
	claims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.jwtExpiry)),
			Issuer:    "ethsy-server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// ValidateToken parses and validates a JWT token, returning the claims.
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.jwtSecret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// GetTokenExpiry returns the configured JWT token expiry duration.
func (m *Manager) GetTokenExpiry() time.Duration {
	return m.jwtExpiry
}

// IsEmailAllowed checks if the email is in the whitelist.
func (m *Manager) IsEmailAllowed(email string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allowedEmails[email]
}

// AddAllowedEmail adds an email to the whitelist.
func (m *Manager) AddAllowedEmail(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedEmails[email] = true
}

// RemoveAllowedEmail removes an email from the whitelist.
func (m *Manager) RemoveAllowedEmail(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.allowedEmails, email)
}

// GetAuthURL returns the Google OAuth2 authorization URL with CSRF state.
func (m *Manager) GetAuthURL(sessionID string) (string, error) {
	state, err := generateRandomState()
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	m.mu.Lock()
	m.states[state] = &OAuthState{
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	m.mu.Unlock()

	return m.oauthCfg.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// ExchangeCode exchanges an OAuth2 authorization code for user info.
// Returns the user's email and the session ID associated with the state.
func (m *Manager) ExchangeCode(ctx context.Context, code, state string) (email string, sessionID string, err error) {
	// Validate and consume the state parameter.
	m.mu.Lock()
	oauthState, ok := m.states[state]
	if ok {
		delete(m.states, state)
	}
	m.mu.Unlock()

	if !ok {
		return "", "", fmt.Errorf("invalid or expired OAuth state")
	}
	if time.Now().After(oauthState.ExpiresAt) {
		return "", "", fmt.Errorf("OAuth state expired")
	}

	sessionID = oauthState.SessionID

	// Exchange the authorization code for a token.
	token, err := m.oauthCfg.Exchange(ctx, code)
	if err != nil {
		return "", "", fmt.Errorf("exchange code: %w", err)
	}

	// Fetch user info from Google.
	userInfo, err := fetchGoogleUserInfo(ctx, m.oauthCfg, token)
	if err != nil {
		return "", "", fmt.Errorf("fetch user info: %w", err)
	}

	if !userInfo.EmailVerified {
		return "", "", fmt.Errorf("email not verified")
	}

	return userInfo.Email, sessionID, nil
}

// CleanupExpiredStates removes expired OAuth state entries.
func (m *Manager) CleanupExpiredStates() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for k, v := range m.states {
		if now.After(v.ExpiresAt) {
			delete(m.states, k)
		}
	}
}

// fetchGoogleUserInfo calls Google's userinfo API with the OAuth2 token.
func fetchGoogleUserInfo(ctx context.Context, cfg *oauth2.Config, token *oauth2.Token) (*GoogleUserInfo, error) {
	client := cfg.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google userinfo returned status %d", resp.StatusCode)
	}

	var info GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return &info, nil
}

// generateRandomState generates a cryptographically random state string.
func generateRandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ExtractBearerToken extracts the JWT token from an Authorization header.
func ExtractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
