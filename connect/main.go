package main

import (
	"fmt"
	"os"

	"github.com/devsigner9920/ethsy-ssh/connect/cmd"
)

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		cmd.Root()
		return
	}

	switch args[0] {
	case "new":
		cmd.New(args[1:])
	case "list":
		cmd.List()
	case "delete":
		cmd.Delete(args[1:])
	case "logout":
		cmd.Logout()
	case "status":
		cmd.Status()
	default:
		fmt.Fprintf(os.Stderr, "알 수 없는 명령어: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "사용법: ethsy [new|list|delete|logout|status]")
		os.Exit(1)
	}
}
