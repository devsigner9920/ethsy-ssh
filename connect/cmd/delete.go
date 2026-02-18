package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/devsigner9920/ethsy-ssh/connect/api"
	"github.com/devsigner9920/ethsy-ssh/connect/config"
	"golang.org/x/term"
)

// Delete handles the "ethsy delete" command with interactive multi-select.
func Delete(args []string) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "설정 파일 로드 실패: %v\n", err)
		os.Exit(1)
	}

	if !cfg.IsAuthenticated() {
		fmt.Fprintf(os.Stderr, "먼저 인증이 필요합니다. 'ethsy'를 실행하세요.\n")
		os.Exit(1)
	}

	client := api.NewClient(cfg.Server, cfg.Token)

	sessions, err := client.ListSessions()
	if err != nil {
		if api.IsAuthError(err) {
			if authErr := doAuthenticate(cfg); authErr != nil {
				fmt.Fprintf(os.Stderr, "%v\n", authErr)
				os.Exit(1)
			}
			client = api.NewClient(cfg.Server, cfg.Token)
			sessions, err = client.ListSessions()
			if err != nil {
				fmt.Fprintf(os.Stderr, "세션 목록 조회 실패: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "세션 목록 조회 실패: %v\n", err)
			os.Exit(1)
		}
	}

	if len(sessions) == 0 {
		fmt.Println("삭제할 세션이 없습니다.")
		return
	}

	fmt.Println()
	selected := interactiveMultiSelect(sessions)
	if selected == nil {
		fmt.Println("취소되었습니다.")
		return
	}

	// Delete selected sessions
	deleted := 0
	for _, idx := range selected {
		s := sessions[idx]
		desc := s.Description
		if desc == "" {
			desc = s.TmuxName
		}
		if err := client.DeleteSession(s.ID); err != nil {
			fmt.Fprintf(os.Stderr, "  세션 '%s' 삭제 실패: %v\n", desc, err)
		} else {
			fmt.Printf("  \033[31m✗\033[0m %s 삭제됨\n", desc)
			deleted++
		}
	}
	fmt.Printf("\n%d개 세션 삭제 완료.\n", deleted)
}

// interactiveMultiSelect shows a multi-select UI for sessions.
// Returns selected indices or nil if cancelled.
func interactiveMultiSelect(sessions []api.Session) []int {
	cursor := 0
	checked := make([]bool, len(sessions))
	mode := "select" // "select" or "confirm"

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Print("\033[?25l") // hide cursor
	defer fmt.Print("\033[?25h")

	renderMultiSelect(sessions, cursor, checked, mode, false)

	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			clearMultiSelect(sessions, mode)
			return nil
		}

		if mode == "confirm" {
			switch {
			case n == 3 && buf[0] == 27 && buf[1] == 91:
				switch buf[2] {
				case 67: // Right arrow → switch to Cancel
					cursor = 1
				case 68: // Left arrow → switch to OK
					cursor = 0
				}
			case buf[0] == 'h': // vim left
				cursor = 0
			case buf[0] == 'l': // vim right
				cursor = 1
			case buf[0] == 9: // Tab
				cursor = 1 - cursor
			case buf[0] == 13 || buf[0] == 10: // Enter
				clearMultiSelect(sessions, mode)
				if cursor == 0 { // OK
					result := []int{}
					for i, c := range checked {
						if c {
							result = append(result, i)
						}
					}
					return result
				}
				return nil // Cancel
			case buf[0] == 'q' || buf[0] == 3: // q or Ctrl+C
				clearMultiSelect(sessions, mode)
				return nil
			case buf[0] == 27 && n == 1: // Escape → back to select
				mode = "select"
				cursor = 0
			}
			renderMultiSelect(sessions, cursor, checked, mode, true)
			continue
		}

		// select mode
		switch {
		case buf[0] == 13 || buf[0] == 10: // Enter → go to confirm
			count := 0
			for _, c := range checked {
				if c {
					count++
				}
			}
			if count == 0 {
				continue
			}
			mode = "confirm"
			cursor = 0 // default to OK
		case buf[0] == ' ': // Space → toggle
			checked[cursor] = !checked[cursor]
			if cursor < len(sessions)-1 {
				cursor++
			}
		case buf[0] == 'a': // Select all
			allChecked := true
			for _, c := range checked {
				if !c {
					allChecked = false
					break
				}
			}
			for i := range checked {
				checked[i] = !allChecked
			}
		case buf[0] == 'q' || buf[0] == 3: // q or Ctrl+C
			clearMultiSelect(sessions, mode)
			return nil
		case n == 3 && buf[0] == 27 && buf[1] == 91:
			switch buf[2] {
			case 65: // Up
				if cursor > 0 {
					cursor--
				}
			case 66: // Down
				if cursor < len(sessions)-1 {
					cursor++
				}
			}
		case buf[0] == 'k':
			if cursor > 0 {
				cursor--
			}
		case buf[0] == 'j':
			if cursor < len(sessions)-1 {
				cursor++
			}
		default:
			continue
		}

		renderMultiSelect(sessions, cursor, checked, mode, true)
	}
}

func renderMultiSelect(sessions []api.Session, cursor int, checked []bool, mode string, redraw bool) {
	totalLines := len(sessions) + 3 // header + sessions + blank + buttons/hint

	if redraw {
		fmt.Printf("\033[%dA\r", totalLines)
	}
	fmt.Print("\033[J")

	// Header
	write("  \033[1;37m삭제할 세션 선택\033[0m  \033[90m↑↓ 이동  Space 선택  a 전체  Enter 확인  q 취소\033[0m\n")

	for i, s := range sessions {
		desc := displayDesc(s.Description)
		if len([]rune(desc)) > 24 {
			desc = string([]rune(desc)[:21]) + "..."
		}
		created := formatTime(s.CreatedAt)

		check := "○"
		if checked[i] {
			check = "\033[31m●\033[0m"
		}

		if mode == "select" && i == cursor {
			write(fmt.Sprintf("  \033[36m❯\033[0m %s \033[1;37m%d. %s\033[0m  \033[90m%s\033[0m\n",
				check, i+1, desc, created))
		} else {
			write(fmt.Sprintf("    %s \033[37m%d. %s\033[0m  \033[90m%s\033[0m\n",
				check, i+1, desc, created))
		}
	}

	write("\n")

	if mode == "confirm" {
		count := 0
		for _, c := range checked {
			if c {
				count++
			}
		}
		msg := fmt.Sprintf("%d개 세션을 삭제합니다. ", count)

		okStyle := "\033[90m"
		cancelStyle := "\033[90m"
		if cursor == 0 {
			okStyle = "\033[1;31m"
		} else {
			cancelStyle = "\033[1;37m"
		}

		write(fmt.Sprintf("  %s%s[ OK ]%s  %s[ Cancel ]\033[0m\n",
			strings.Repeat(" ", 0), okStyle, "\033[0m "+cancelStyle, "\033[0m"))
		_ = msg
		write(fmt.Sprintf("  \033[90m%s\033[0m\n", msg))
	} else {
		count := 0
		for _, c := range checked {
			if c {
				count++
			}
		}
		if count > 0 {
			write(fmt.Sprintf("  \033[90m%d개 선택됨\033[0m\n", count))
		} else {
			write("  \033[90mSpace로 세션을 선택하세요\033[0m\n")
		}
	}
}

func clearMultiSelect(sessions []api.Session, mode string) {
	totalLines := len(sessions) + 3
	fmt.Printf("\033[%dA\r", totalLines)
	fmt.Print("\033[J")
}
