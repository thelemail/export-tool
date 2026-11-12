package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/thelemail/trust/opaque"
	"github.com/thelemail/trust/vault"
	"golang.org/x/term"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/export"
)

var errAuth = errors.New("invalid email or password")

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
		if !errors.Is(err, export.ErrIncomplete) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, apiBase, webOrigin, email, password, out string) error {
	client := api.New(apiBase, webOrigin)

	params, err := client.OpaqueParameters(ctx)
	if err != nil {
		return fmt.Errorf("fetch opaque parameters: %w", err)
	}
	pinned := opaque.Params{
		Version: params.OpaqueParamsVersion,
		OPRF:    params.OPRF,
		AKE:     params.AKE,
		KDF:     params.KDF,
		MAC:     params.MAC,
		Hash:    params.Hash,
		KSF: opaque.KSFParams{
			Name:         params.KSF.Name,
			TimeCost:     params.KSF.TimeCost,
			MemoryKiB:    params.KSF.MemoryKib,
			Threads:      params.KSF.Threads,
			Salt:         params.KSF.Salt,
			OutputLength: params.KSF.OutputLength,
		},
	}
	if err := pinned.RequirePinned(); err != nil {
		return err
	}

	auth := opaque.NewStore()
	defer auth.LockAll()
	keys := vault.NewStore(auth)
	defer keys.LockAll()

	login, err := auth.StartLogin(password, pinned)
	if err != nil {
		return err
	}
	defer auth.Abandon(login.OperationID)
	ke1, err := base64.StdEncoding.DecodeString(login.Message)
	if err != nil {
		return err
	}

	init, err := client.LoginInit(ctx, email, ke1)
	if err != nil {
		return fmt.Errorf("login init: %w", err)
	}
	if init.AccountID == "" || len(init.KE2) == 0 {
		return errAuth
	}
	finished, err := auth.FinishLogin(login.OperationID, init.AccountID, base64.StdEncoding.EncodeToString(init.KE2), false)
	if err != nil {
		return errAuth
	}
	ke3, err := base64.StdEncoding.DecodeString(finished.KE3)
	if err != nil {
		return err
	}

	grant, err := client.LoginComplete(ctx, init.ChallengeID, ke3)
	if err != nil {
		return fmt.Errorf("login complete: %w", err)
	}
	if grant.TwoFactor != nil {
		grant, err = solveTwoFactor(ctx, client, grant.TwoFactor)
		if err != nil {
			return err
		}
	}
	if grant.AccessToken == "" {
		return fmt.Errorf("login complete: unexpected server response")
	}
	client.SetSession(grant.AccessToken, grant.AccountID)
	fmt.Println("Signed in.")

	keyList, err := client.ListMyKeys(ctx)
	if err != nil {
		return fmt.Errorf("list account keys: %w", err)
	}
	if _, err := auth.CompleteLoginUnlock(login.OperationID, init.AccountID,
		base64.StdEncoding.EncodeToString(grant.WrappedMasterKey),
		base64.StdEncoding.EncodeToString(grant.MasterKeyID)); err != nil {
		return fmt.Errorf("unlock mailbox key: %w", err)
	}
	mailbox, accountKeys, err := export.UnlockAccountKeys(keys, init.AccountID, keyList, func(set vault.KeySet) error {
		return keys.OpenFromOpaque(init.AccountID, set)
	})
	if err != nil {
		return fmt.Errorf("unlock mailbox key: %w", err)
	}
	printKeys(accountKeys)
	var refused *export.ProductKeysRefused
	switch _, err := export.VerifyProductKeys(ctx, client, keys, init.AccountID); {
	case errors.As(err, &refused) && !refused.Enforced:
		fmt.Fprintln(os.Stderr, "warning: account keys did not verify:", err)
	case err != nil:
		return fmt.Errorf("verify account keys: %w", err)
	}

	var session string
	if hb, err := client.ExportHeartbeat(ctx, ""); err == nil {
		session = hb.SessionID
	}

	e := &export.Exporter{
		Client:  client,
		Vault:   mailbox,
		OutDir:  out,
		Session: session,
		Keys:    accountKeys,
	}
	return e.Run(ctx)
}

func printKeys(keys []export.AccountKey) {
	unlocked := 0
	for _, k := range keys {
		if k.UnlockError == "" {
			unlocked++
			continue
		}
		fmt.Fprintf(os.Stderr, "warning: key version %d (%s) could not be unlocked: %s\n", k.Version, k.Fingerprint, k.UnlockError)
	}
	if len(keys) == 1 {
		fmt.Println("Unlocked your key.")
		return
	}
	fmt.Printf("Unlocked %d of %d keys.\n", unlocked, len(keys))
}

func solveTwoFactor(ctx context.Context, client *api.Client, ch *api.TwoFactorChallenge) (api.LoginSessionGrant, error) {
	useBackup := true
	for _, m := range ch.Methods {
		if m == "totp" {
			useBackup = false
		}
	}
	if useBackup {
		code := strings.TrimSpace(promptSecret("Backup code: "))
		return client.VerifyBackupCode(ctx, ch.PendingToken, code)
	}
	code := strings.TrimSpace(promptSecret("Authenticator code: "))
	return client.VerifyTOTP(ctx, ch.PendingToken, code)
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
