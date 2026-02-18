package cmd

import (
	"fmt"
	"os"

	"github.com/devsigner9920/ethsy-ssh/connect/api"
	"github.com/devsigner9920/ethsy-ssh/connect/config"
	"github.com/devsigner9920/ethsy-ssh/connect/keys"
)

// Logout handles the "ethsy logout" command.
func Logout() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "설정 파일 로드 실패: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("이 디바이스의 인증 정보를 삭제합니다.")

	// Attempt to revoke the key on the server if we have credentials
	if cfg.Token != "" {
		pubKey, err := keys.LoadPublicKey(config.KeyDir())
		if err == nil && pubKey != "" {
			client := api.NewClient(cfg.Server, cfg.Token)
			if err := client.RevokeKey(pubKey); err != nil {
				// Log but don't fail - we still want to clean up locally
				fmt.Fprintf(os.Stderr, "서버에서 키 제거 중 오류: %v\n", err)
			} else {
				fmt.Println("SSH 키가 서버에서 제거되었습니다.")
			}
		}
	}

	// Delete local config and keys
	if err := config.Delete(); err != nil {
		fmt.Fprintf(os.Stderr, "로컬 데이터 삭제 실패: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("로그아웃 완료.")
}
