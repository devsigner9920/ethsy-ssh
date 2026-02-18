package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/devsigner9920/ethsy-ssh/connect/api"
	"github.com/devsigner9920/ethsy-ssh/connect/config"
)

// List handles the "ethsy list" command.
func List() {
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
		fmt.Println("세션이 없습니다.")
		return
	}

	fmt.Printf("\n%s의 세션:\n\n", cfg.Email)
	printSessionTable(sessions)
	fmt.Println()
}

// printSessionTable prints a formatted table of sessions.
func printSessionTable(sessions []api.Session) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  #\t설명\t상태\t생성일\n")
	fmt.Fprintf(w, "  -\t--\t--\t----\n")
	for i, s := range sessions {
		desc := displayDesc(s.Description)
		status := s.Status
		if status == "" {
			status = "-"
		}
		fmt.Fprintf(w, "  %d\t%s\t%s\t%s\n", i+1, desc, status, formatTime(s.CreatedAt))
	}
	w.Flush()
}
