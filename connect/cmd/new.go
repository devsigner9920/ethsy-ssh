package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/devsigner9920/ethsy-ssh/connect/api"
	"github.com/devsigner9920/ethsy-ssh/connect/config"
)

// New handles the "ethsy new [description]" command.
func New(args []string) {
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

	description := strings.Join(args, " ")

	session, err := client.CreateSession(description)
	if err != nil {
		if api.IsAuthError(err) {
			if authErr := doAuthenticate(cfg); authErr != nil {
				fmt.Fprintf(os.Stderr, "%v\n", authErr)
				os.Exit(1)
			}
			client = api.NewClient(cfg.Server, cfg.Token)
			session, err = client.CreateSession(description)
			if err != nil {
				fmt.Fprintf(os.Stderr, "세션 생성 실패: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "세션 생성 실패: %v\n", err)
			os.Exit(1)
		}
	}

	if err := SSHConnect(session.TmuxName); err != nil {
		fmt.Fprintf(os.Stderr, "SSH 접속 실패: %v\n", err)
		os.Exit(1)
	}
}
