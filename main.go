package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/thelemail/export-tool/transfer"
)

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
)

func main() {
	apiBase := flag.String("api", "https://api.thelemail.com", "Thelemail API base URL")
	webOrigin := flag.String("origin", "https://app.thelemail.com", "Origin header for cookie-authenticated routes")
	email := flag.String("email", "", "Your Thelemail address")
	out := flag.String("out", "thelemail-export", "Output directory")
	version := flag.Bool("version", false, "Print the version and the commit it was built from")
	flag.Parse()

	if *version {
		fmt.Printf("thelemail export-tool %s\ncommit: %s\n", buildVersion, buildCommit)
		return
	}

	if *email == "" {
		fmt.Print("Email: ")
		*email = strings.TrimSpace(readLine())
	}
	if *email == "" {
		fmt.Fprintln(os.Stderr, "an email address is required")
		os.Exit(2)
	}
	password := promptSecret("Password: ")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, *apiBase, *webOrigin, *email, password, *out); err != nil {
		if !errors.Is(err, transfer.ErrIncomplete) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, apiBase, webOrigin, email, password, out string) error {
	s, err := transfer.Login(ctx, apiBase, webOrigin, email, password, promptFactor, os.Stdout, os.Stderr)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Export(ctx, out, os.Stdout, nil)
}

func promptFactor(methods []string) (string, string, error) {
	if slices.Contains(methods, "totp") {
		return "totp", strings.TrimSpace(promptSecret("Authenticator code: ")), nil
	}
	if slices.Contains(methods, "backupCode") {
		return "backupCode", strings.TrimSpace(promptSecret("Backup code: ")), nil
	}
	return "", "", errors.New("no supported second factor on this account")
}

var stdin = bufio.NewReader(os.Stdin)

func readLine() string {
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}

func promptSecret(prompt string) string {
	fmt.Print(prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			return string(b)
		}
	}
	return strings.TrimSpace(readLine())
}
