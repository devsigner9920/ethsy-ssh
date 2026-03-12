package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	pollInterval = 1 * time.Second
	pollTimeout  = 2 * time.Minute
)

// pollResponse represents the JSON body returned by the auth poll endpoint.
type pollResponse struct {
	Token string `json:"token"`
}

// GenerateSessionID creates a UUID v4 string using crypto/rand.
func GenerateSessionID() (string, error) {
	var uuid [16]byte
	if _, err := io.ReadFull(rand.Reader, uuid[:]); err != nil {
		return "", fmt.Errorf("UUID 생성 실패: %w", err)
	}

	// Set version 4
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant bits
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4],
		uuid[4:6],
		uuid[6:8],
		uuid[8:10],
		uuid[10:16],
	), nil
}

// OpenBrowser opens the given URL in the default browser.
func OpenBrowser(url string) error {
	var candidates [][]string

	switch runtime.GOOS {
	case "darwin":
		candidates = [][]string{{"open", url}}
	case "linux":
		isTermux := os.Getenv("TERMUX_VERSION") != "" ||
			os.Getenv("PREFIX") == "/data/data/com.termux/files/usr" ||
			strings.Contains(os.Getenv("HOME"), "/data/data/com.termux")

		if isTermux {
			// Termux/Android: absolute paths only (avoid LookPath/faccessat2 SIGSYS).
			candidates = append(candidates,
				[]string{"/data/data/com.termux/files/usr/bin/termux-open-url", url},
				[]string{"/system/bin/am", "start", "-a", "android.intent.action.VIEW", "-d", url},
			)
		} else {
			// Non-Termux Linux: absolute common paths first, then explicit fallback.
			candidates = append(candidates,
				[]string{"/usr/bin/xdg-open", url},
				[]string{"/bin/xdg-open", url},
				[]string{"/usr/bin/gio", "open", url},
			)
		}
	default:
		return fmt.Errorf("지원하지 않는 운영체제: %s", runtime.GOOS)
	}

	// On some Android/Termux environments, process spawning may be blocked by seccomp.
	// In that case, user can open printed URL manually; do not crash auth flow.
	if os.Getenv("ANDROID_ROOT") != "" && runtime.GOOS == "linux" {
		return nil
	}

	var lastErr error
	for _, c := range candidates {
		if len(c) == 0 {
			continue
		}
		if strings.HasPrefix(c[0], "/") {
			if _, err := os.Stat(c[0]); err != nil {
				lastErr = err
				continue
			}
		}
		cmd := exec.Command(c[0], c[1:]...)
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	if lastErr != nil {
		return fmt.Errorf("브라우저를 열 수 없습니다: %w", lastErr)
	}
	return fmt.Errorf("브라우저를 열 수 없습니다")
}

// Authenticate runs the full OAuth flow: generate session ID, open browser,
// poll for the token. Returns the JWT token on success.
func Authenticate(server string) (string, error) {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return "", err
	}

	authURL := fmt.Sprintf("https://%s/auth?session=%s", server, sessionID)
	pollURL := fmt.Sprintf("https://%s/api/auth/poll?session=%s", server, sessionID)

	fmt.Println("ethsy.me에 접속하려면 인증이 필요합니다.")
	fmt.Println("브라우저에서 로그인 페이지를 여는 중...")
	fmt.Println()
	fmt.Println("브라우저가 열리지 않으면 아래 URL을 직접 열어주세요:")
	fmt.Println(authURL)
	fmt.Println()

	_ = OpenBrowser(authURL)

	fmt.Println("인증 대기 중...")

	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(pollTimeout)

	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)

		resp, err := client.Get(pollURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			var pr pollResponse
			if err := json.Unmarshal(body, &pr); err != nil {
				continue
			}

			if pr.Token != "" {
				return pr.Token, nil
			}
		} else {
			resp.Body.Close()
		}
	}

	return "", fmt.Errorf("인증 시간이 초과되었습니다. 다시 시도하세요")
}
