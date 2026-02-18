package cmd

import (
	"fmt"
	"os"

	"github.com/devsigner9920/ethsy-ssh/connect/config"
)

// Status handles the "ethsy status" command.
func Status() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "설정 파일 로드 실패: %v\n", err)
		os.Exit(1)
	}

	if !cfg.IsAuthenticated() {
		fmt.Println("인증되지 않은 상태입니다. 'ethsy'를 실행하여 인증하세요.")
		return
	}

	fmt.Printf("이메일: %s\n", cfg.Email)
	fmt.Printf("유저네임: %s\n", cfg.Username)
	fmt.Printf("홈 디렉터리: ~/%s\n", cfg.Username)
	fmt.Printf("디바이스 키: %s\n", config.PrivateKeyPath())

	expiry := cfg.TokenExpiry()
	if !expiry.IsZero() {
		fmt.Printf("토큰 만료: %s\n", expiry.Format("2006-01-02"))
	} else {
		fmt.Println("토큰 만료: 알 수 없음")
	}
}
