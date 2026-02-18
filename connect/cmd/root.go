package cmd

import (
	"fmt"
	"os"

	"github.com/devsigner9920/ethsy-ssh/connect/api"
	"github.com/devsigner9920/ethsy-ssh/connect/auth"
	"github.com/devsigner9920/ethsy-ssh/connect/config"
	"github.com/devsigner9920/ethsy-ssh/connect/keys"
)

// Root handles the default command (ethsy with no subcommand).
func Root() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "설정 파일 로드 실패: %v\n", err)
		os.Exit(1)
	}

	// Step 1: Ensure authenticated
	if !cfg.IsAuthenticated() {
		if err := doAuthenticate(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}

	client := api.NewClient(cfg.Server, cfg.Token)

	// Step 2: Check user registration
	userInfo, err := client.GetMe()
	if err != nil {
		if api.IsAuthError(err) {
			// Token expired, re-authenticate
			if err := doAuthenticate(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
			client = api.NewClient(cfg.Server, cfg.Token)
			userInfo, err = client.GetMe()
			if err != nil {
				fmt.Fprintf(os.Stderr, "사용자 정보 조회 실패: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "사용자 정보 조회 실패: %v\n", err)
			os.Exit(1)
		}
	}

	if userInfo == nil {
		// New user - needs registration
		doRegisterNewUser(cfg, client)
	} else if !hasLocalKey() {
		// Existing user, new device - register key
		doRegisterKey(cfg, client, userInfo)
	} else {
		// Update config with latest info from server
		cfg.Username = userInfo.Username
		cfg.Save()
	}

	// Step 3: List sessions and connect
	doSessionConnect(cfg, client)
}

// doAuthenticate runs the OAuth flow and saves credentials.
func doAuthenticate(cfg *config.Config) error {
	token, err := auth.Authenticate(cfg.Server)
	if err != nil {
		return err
	}

	email, err := config.ExtractEmail(token)
	if err != nil {
		return fmt.Errorf("토큰 파싱 실패: %v", err)
	}

	cfg.Token = token
	cfg.Email = email

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("설정 저장 실패: %v", err)
	}

	fmt.Printf("\n인증 완료! (%s)\n", email)
	return nil
}

// doRegisterNewUser handles the new user registration flow.
func doRegisterNewUser(cfg *config.Config, client *api.Client) {
	// Generate SSH key
	pubKey, err := keys.EnsureKeys(config.KeyDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "SSH 키 생성 실패: %v\n", err)
		os.Exit(1)
	}

	// Prompt for username
	var username string
	fmt.Print("사용할 이름을 입력하세요 (홈 디렉터리로 사용됩니다): ")
	fmt.Scanln(&username)

	for {
		if username == "" {
			fmt.Print("사용할 이름을 입력하세요 (홈 디렉터리로 사용됩니다): ")
			fmt.Scanln(&username)
			continue
		}

		userInfo, err := client.Register(username, pubKey)
		if err != nil {
			if api.IsConflictError(err) {
				fmt.Print("이미 사용 중인 이름입니다. 다른 이름을 입력하세요: ")
				fmt.Scanln(&username)
				continue
			}
			fmt.Fprintf(os.Stderr, "등록 실패: %v\n", err)
			os.Exit(1)
		}

		cfg.Username = userInfo.Username
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "설정 저장 실패: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("등록 완료! 홈 디렉터리: ~/%s\n", userInfo.Username)
		break
	}
}

// doRegisterKey handles the existing user + new device flow.
func doRegisterKey(cfg *config.Config, client *api.Client, userInfo *api.UserInfo) {
	fmt.Println("이 디바이스의 SSH 키를 등록하는 중...")

	pubKey, err := keys.EnsureKeys(config.KeyDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "SSH 키 생성 실패: %v\n", err)
		os.Exit(1)
	}

	if err := client.RegisterKey(pubKey); err != nil {
		fmt.Fprintf(os.Stderr, "키 등록 실패: %v\n", err)
		os.Exit(1)
	}

	cfg.Username = userInfo.Username
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "설정 저장 실패: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("등록 완료!")
}

// doSessionConnect lists sessions and connects to the selected one.
func doSessionConnect(cfg *config.Config, client *api.Client) {
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

	switch len(sessions) {
	case 0:
		// No sessions - auto-create
		fmt.Println("세션이 없습니다. 새 세션을 생성합니다...")
		session, err := client.CreateSession("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "세션 생성 실패: %v\n", err)
			os.Exit(1)
		}
		if err := SSHConnect(session.TmuxName); err != nil {
			fmt.Fprintf(os.Stderr, "SSH 접속 실패: %v\n", err)
			os.Exit(1)
		}

	case 1:
		// Single session - auto-connect
		if err := SSHConnect(sessions[0].TmuxName); err != nil {
			fmt.Fprintf(os.Stderr, "SSH 접속 실패: %v\n", err)
			os.Exit(1)
		}

	default:
		// Multiple sessions - interactive selector
		fmt.Printf("\n%s의 세션:\n\n", cfg.Email)

		choice := interactiveSelect(sessions)
		if choice < 0 {
			fmt.Println("취소되었습니다.")
			os.Exit(0)
		}

		selected := sessions[choice]
		fmt.Printf("세션 %s에 접속합니다...\n", selected.TmuxName)
		if err := SSHConnect(selected.TmuxName); err != nil {
			fmt.Fprintf(os.Stderr, "SSH 접속 실패: %v\n", err)
			os.Exit(1)
		}
	}
}

// hasLocalKey checks if a local SSH key already exists.
func hasLocalKey() bool {
	_, err := os.Stat(config.PublicKeyPath())
	return err == nil
}
