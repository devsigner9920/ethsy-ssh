package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client wraps HTTP communication with the ethsy server API.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewClient creates a new API client.
func NewClient(server, token string) *Client {
	return &Client{
		BaseURL: fmt.Sprintf("https://%s", server),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// UserInfo represents the response from GET /api/me.
type UserInfo struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

// Session represents a tmux session from the API.
type Session struct {
	ID          int    `json:"id"`
	TmuxName    string `json:"tmux_name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

// RegisterRequest is the body for POST /api/register.
type RegisterRequest struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

// RegisterKeyRequest is the body for POST /api/register-key.
type RegisterKeyRequest struct {
	PublicKey string `json:"public_key"`
}

// RevokeKeyRequest is the body for POST /api/revoke-key.
type RevokeKeyRequest struct {
	PublicKey string `json:"public_key"`
}

// CreateSessionRequest is the body for POST /api/sessions.
type CreateSessionRequest struct {
	Description string `json:"description"`
}

// GetMe fetches the current user info. Returns (nil, nil) if the user
// does not exist (404).
func (c *Client) GetMe() (*UserInfo, error) {
	resp, err := c.doRequest("GET", "/api/me", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &AuthError{}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, readErrorResponse(resp)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("응답 파싱 실패: %w", err)
	}

	return &info, nil
}

// Register registers a new user with the given username and public key.
// Returns a ConflictError if the username is taken (409).
func (c *Client) Register(username, publicKey string) (*UserInfo, error) {
	body := RegisterRequest{
		Username:  username,
		PublicKey: publicKey,
	}

	resp, err := c.doRequest("POST", "/api/register", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return nil, &ConflictError{}
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("접근 권한이 없습니다. 관리자에게 문의하세요")
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, readErrorResponse(resp)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("응답 파싱 실패: %w", err)
	}

	return &info, nil
}

// RegisterKey registers an SSH key for an existing user on a new device.
func (c *Client) RegisterKey(publicKey string) error {
	body := RegisterKeyRequest{
		PublicKey: publicKey,
	}

	resp, err := c.doRequest("POST", "/api/register-key", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return &AuthError{}
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return readErrorResponse(resp)
	}

	return nil
}

// RevokeKey revokes an SSH key from the server.
func (c *Client) RevokeKey(publicKey string) error {
	body := RevokeKeyRequest{
		PublicKey: publicKey,
	}

	resp, err := c.doRequest("POST", "/api/revoke-key", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return &AuthError{}
	}

	if resp.StatusCode != http.StatusOK {
		return readErrorResponse(resp)
	}

	return nil
}

// ListSessions returns all sessions for the authenticated user.
func (c *Client) ListSessions() ([]Session, error) {
	resp, err := c.doRequest("GET", "/api/sessions", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &AuthError{}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, readErrorResponse(resp)
	}

	var sessions []Session
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("응답 파싱 실패: %w", err)
	}

	return sessions, nil
}

// CreateSession creates a new tmux session with the given description.
func (c *Client) CreateSession(description string) (*Session, error) {
	body := CreateSessionRequest{
		Description: description,
	}

	resp, err := c.doRequest("POST", "/api/sessions", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &AuthError{}
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, readErrorResponse(resp)
	}

	var session Session
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, fmt.Errorf("응답 파싱 실패: %w", err)
	}

	return &session, nil
}

// DeleteSession deletes a session by ID.
func (c *Client) DeleteSession(id int) error {
	path := fmt.Sprintf("/api/sessions/%d", id)

	resp, err := c.doRequest("DELETE", path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return &AuthError{}
	}

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("세션을 찾을 수 없습니다")
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return readErrorResponse(resp)
	}

	return nil
}

// doRequest builds and executes an authenticated HTTP request.
func (c *Client) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("요청 생성 실패: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("요청 생성 실패: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect.ethsy.me에 연결할 수 없습니다")
	}

	return resp, nil
}

// readErrorResponse extracts an error message from a non-success response.
func readErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("서버 오류 (상태 코드: %d)", resp.StatusCode)
	}

	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &errResp) == nil {
		if errResp.Error != "" {
			return fmt.Errorf("%s", errResp.Error)
		}
		if errResp.Message != "" {
			return fmt.Errorf("%s", errResp.Message)
		}
	}

	return fmt.Errorf("서버 오류 (상태 코드: %d)", resp.StatusCode)
}

// AuthError indicates the token is expired or invalid.
type AuthError struct{}

func (e *AuthError) Error() string {
	return "인증이 만료되었습니다"
}

// ConflictError indicates a 409 conflict (e.g., username taken).
type ConflictError struct{}

func (e *ConflictError) Error() string {
	return "이미 사용 중인 이름입니다"
}

// IsAuthError checks if the error is an authentication error.
func IsAuthError(err error) bool {
	_, ok := err.(*AuthError)
	return ok
}

// IsConflictError checks if the error is a conflict error.
func IsConflictError(err error) bool {
	_, ok := err.(*ConflictError)
	return ok
}
