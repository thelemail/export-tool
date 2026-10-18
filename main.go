package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/crypto"
	"github.com/thelemail/export-tool/internal/export"
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
	if err := crypto.VerifyParameters(crypto.Parameters{
		Version:         params.OpaqueParamsVersion,
		OPRF:            params.OPRF,
		AKE:             params.AKE,
		KDF:             params.KDF,
		MAC:             params.MAC,
		Hash:            params.Hash,
		KSFName:         params.KSF.Name,
		TimeCost:        params.KSF.TimeCost,
		MemoryKiB:       params.KSF.MemoryKib,
		Threads:         params.KSF.Threads,
		Salt:            params.KSF.Salt,
		KSFOutputLength: params.KSF.OutputLength,
	}); err != nil {
		return err
	}

	login, ke1, err := crypto.StartLogin(password)
	if err != nil {
		return err
	}
	defer login.Close()

	init, err := client.LoginInit(ctx, email, ke1)
	if err != nil {
		return fmt.Errorf("login init: %w", err)
	}
	if init.AccountID == "" || len(init.KE2) == 0 {
		return crypto.ErrAuth
	}
	ke3, exportKey, err := login.Finish(init.AccountID, init.KE2)
	if err != nil {
		return err
	}
	defer zero(exportKey)

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
	vault, keys, err := unlock(exportKey, grant, keyList)
	if err != nil {
		return err
	}
	printKeys(keys)

	var session string
	if hb, err := client.ExportHeartbeat(ctx, ""); err == nil {
		session = hb.SessionID
	}

	e := &export.Exporter{
		Client:  client,
		Vault:   vault,
		OutDir:  out,
		Session: session,
		Keys:    keys,
	}
	return e.Run(ctx)
}

func unlock(exportKey []byte, grant api.LoginSessionGrant, keyList api.AccountKeysResponse) (*crypto.Vault, []export.AccountKey, error) {
	amk, err := crypto.UnwrapMasterKey(exportKey, grant.WrappedMasterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("unlock mailbox key: %w", err)
	}
	defer zero(amk)

	id, err := crypto.DeriveMasterKeyID(amk)
	if err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(id, grant.MasterKeyID) != 1 {
		return nil, nil, fmt.Errorf("unlock mailbox key: master key does not match the account")
	}

	passphrase, err := crypto.DerivePGPPassphrase(amk)
	if err != nil {
		return nil, nil, err
	}
	pass := []byte(passphrase)
	defer zero(pass)
	vault, keys, err := export.UnlockAccountKeys(keyList, pass)
	if err != nil {
		return nil, nil, fmt.Errorf("unlock mailbox key: %w", err)
	}
	return vault, keys, nil
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

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
