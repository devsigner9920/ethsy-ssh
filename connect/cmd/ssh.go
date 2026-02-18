package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/devsigner9920/ethsy-ssh/connect/config"
)

// SSHConnect replaces the current process with an ssh command that attaches
// to the specified tmux session on ethsy.me.
func SSHConnect(tmuxName string) error {
	keyPath := config.PrivateKeyPath()

	// Verify the private key exists
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("SSH 키를 찾을 수 없습니다: %s", keyPath)
	}

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh를 찾을 수 없습니다: %w", err)
	}

	args := []string{
		"ssh",
		"-t",
		"-i", keyPath,
		"-p", "9920",
		"-o", "StrictHostKeyChecking=no",
		"ethsy@ssh.ethsy.me",
		fmt.Sprintf("bash -l -c 'tmux attach -t %s'", tmuxName),
	}

	// Filter out Claude Code env vars to prevent nested session detection.
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if len(e) >= 10 && e[:10] == "CLAUDECODE" || len(e) >= 11 && e[:11] == "CLAUDE_CODE" {
			continue
		}
		env = append(env, e)
	}

	// Replace current process with ssh using syscall.Exec
	return syscall.Exec(sshPath, args, env)
}
