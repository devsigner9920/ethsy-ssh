package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/devsigner9920/ethsy-ssh/connect/api"
	"golang.org/x/term"
)

// write outputs a string using \r\n for raw mode compatibility.
func write(s string) {
	// In raw mode, \n doesn't do carriage return, so replace with \r\n
	s = strings.ReplaceAll(s, "\n", "\r\n")
	fmt.Print(s)
}

// interactiveSelect shows an interactive session selector with arrow keys.
// Returns the selected index (0-based) or -1 if cancelled.
func interactiveSelect(sessions []api.Session) int {
	if len(sessions) == 0 {
		return -1
	}

	selected := 0

	// Switch to raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return -1
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Hide cursor
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h")

	// Initial render
	renderSelector(sessions, selected, false)

	buf := make([]byte, 3)

	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			clearSelector(len(sessions))
			return -1
		}

		switch {
		case buf[0] == 13 || buf[0] == 10: // Enter
			clearSelector(len(sessions))
			return selected
		case buf[0] == 'q' || buf[0] == 3: // q or Ctrl+C
			clearSelector(len(sessions))
			return -1
		case n == 3 && buf[0] == 27 && buf[1] == 91: // Arrow keys
			switch buf[2] {
			case 65: // Up
				if selected > 0 {
					selected--
				}
			case 66: // Down
				if selected < len(sessions)-1 {
					selected++
				}
			}
		case buf[0] == 'k': // vim up
			if selected > 0 {
				selected--
			}
		case buf[0] == 'j': // vim down
			if selected < len(sessions)-1 {
				selected++
			}
		default:
			continue
		}

		renderSelector(sessions, selected, true)
	}
}

func renderSelector(sessions []api.Session, selected int, redraw bool) {
	totalLines := len(sessions) + 1 // header + sessions

	if redraw {
		// Move cursor up to beginning of selector
		fmt.Printf("\033[%dA\r", totalLines)
	}

	// Clear from cursor down
	fmt.Print("\033[J")

	// Header
	write("  \033[1;37m세션 선택\033[0m  \033[90m↑↓ 이동  Enter 선택  q 취소\033[0m\n")

	for i, s := range sessions {
		desc := displayDesc(s.Description)
		if len([]rune(desc)) > 24 {
			desc = string([]rune(desc)[:21]) + "..."
		}
		status := formatStatus(s.Status)
		created := formatTime(s.CreatedAt)

		if i == selected {
			write(fmt.Sprintf("  \033[36m❯\033[0m \033[1;36m%d. %s\033[0m  %s  \033[36m%s\033[0m\n",
				i+1, desc, status, created))
		} else {
			write(fmt.Sprintf("    \033[37m%d. %s\033[0m  %s  \033[90m%s\033[0m\n",
				i+1, desc, status, created))
		}
	}
}

func clearSelector(sessionCount int) {
	totalLines := sessionCount + 1
	fmt.Printf("\033[%dA\r", totalLines)
	fmt.Print("\033[J")
}

func displayDesc(desc string) string {
	if desc == "" {
		return "(설명 없음)"
	}
	return desc
}

func formatStatus(status string) string {
	switch strings.ToLower(status) {
	case "active":
		return "\033[32m● active \033[0m"
	case "stopped":
		return "\033[31m○ stopped\033[0m"
	default:
		if status == "" {
			return "\033[90m  -     \033[0m"
		}
		return fmt.Sprintf("  %-7s", status)
	}
}

func formatTime(timeStr string) string {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return timeStr
	}
	return t.Local().Format("01/02 15:04")
}
