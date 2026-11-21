package transfer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/thelemail/export-tool/internal/api"
	"github.com/thelemail/export-tool/internal/export"
	"github.com/thelemail/trust/opaque"
	"github.com/thelemail/trust/vault"
)

var ErrIncomplete = export.ErrIncomplete

type Config struct {
	API    string
	Web    string
	Client string
}

type ProductKeys struct {
	Problem error
}

func (p ProductKeys) Verified() bool { return p.Problem == nil }

type FactorPrompt func(methods []string) (method, code string, err error)

type Session struct {
	ProductKeys      ProductKeys
	PublicKeyArmored string
	Fingerprint      []byte
	BaseURL          string
	AccountID        string
	client           *api.Client
	store            *vault.Store
	mailbox          *export.Vault
	keys             []export.AccountKey
}

func (s *Session) Do(req *http.Request) (*http.Response, error) { return s.client.Do(req) }

func (s *Session) VerifyProductKeys(ctx context.Context) ProductKeys {
	s.ProductKeys = verifyProductKeys(ctx, s.client, s.store, s.AccountID)
	return s.ProductKeys
}

func verifyProductKeys(ctx context.Context, client *api.Client, store *vault.Store, account string) ProductKeys {
	if _, err := export.VerifyProductKeys(ctx, client, store, account); err != nil {
		return ProductKeys{Problem: err}
	}
	return ProductKeys{}
}

func (s *Session) Close() {
	s.store.LockAll()
	s.client.Close()
}

func (s *Session) Export(ctx context.Context, out string, output io.Writer, progress func(folder string, messages int)) error {
	var sessionID string
	if heartbeat, err := s.client.ExportHeartbeat(ctx, ""); err == nil {
		sessionID = heartbeat.SessionID
	}
	e := &export.Exporter{
		Client: s.client, Vault: s.mailbox, Keys: s.keys,
		OutDir: out, Session: sessionID, Output: output, Progress: progress,
	}
	return e.Run(ctx)
}

type PasskeyRequest struct {
	Options json.RawMessage
	Expires time.Time
}

type LoginFactors struct {
	Prompt  func(ctx context.Context, methods []string, message string) (method, code string, err error)
	Passkey func(context.Context, PasskeyRequest) (json.RawMessage, error)
}

func solveTwoFactor(ctx context.Context, client *api.Client, ch *api.TwoFactorChallenge, factors LoginFactors) (api.LoginSessionGrant, error) {
	var grant api.LoginSessionGrant
	if factors.Prompt == nil || ch.PendingToken == "" {
		return grant, ErrNoSecondFactor
	}
	if ch.ExpiresInSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(ch.ExpiresInSeconds))
		defer cancel()
	}
	message := ""
	for {
		method, code, err := factors.Prompt(ctx, ch.Methods, message)
		if err != nil {
			return grant, err
		}
		if !slices.Contains(ch.Methods, method) {
			return grant, errors.New("selected second factor is unavailable")
		}
		switch method {
		case "totp":
			grant, err = client.VerifyTOTP(ctx, ch.PendingToken, strings.TrimSpace(code))
		case "backupCode":
			grant, err = client.VerifyBackupCode(ctx, ch.PendingToken, strings.TrimSpace(code))
		case "webauthn":
			if factors.Passkey == nil {
				return grant, errors.New("passkeys are unavailable in this client")
			}
			grant, err = verifyPasskey(ctx, client, ch.PendingToken, factors.Passkey)
			var dismissed *browserError
			if errors.As(err, &dismissed) && ctx.Err() == nil {
				message = err.Error()
				continue
			}
		default:
			return grant, errors.New("unsupported second factor")
		}
		var apiErr *api.HTTPError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized && ctx.Err() == nil {
			message = "Verification was declined. Try again or choose another method."
			continue
		}
		if errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusGone) {
			return grant, because(ErrVerificationExpired, err)
		}
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
			return grant, because(ErrVerificationExpired, err)
		}
		if err != nil {
			return grant, classify(err)
		}
		return grant, nil
	}
}

func verifyPasskey(ctx context.Context, client *api.Client, pending string, run func(context.Context, PasskeyRequest) (json.RawMessage, error)) (api.LoginSessionGrant, error) {
	var grant api.LoginSessionGrant
	options, err := client.WebauthnLoginInit(ctx, pending)
	if err != nil {
		return grant, err
	}
	req := PasskeyRequest{Options: options}
	if deadline, ok := ctx.Deadline(); ok {
		req.Expires = deadline
	}
	credential, err := run(ctx, req)
	if err != nil {
		return grant, &browserError{err}
	}
	if len(credential) == 0 || credential[0] != '{' {
		return grant, errors.New("missing browser passkey response")
	}
	return client.VerifyPasskey(ctx, pending, credential)
}

func Login(ctx context.Context, apiBase, webOrigin, email, password string, prompt FactorPrompt, output, warnings io.Writer) (*Session, error) {
	factors := LoginFactors{}
	if prompt != nil {
		factors.Prompt = func(_ context.Context, methods []string, message string) (string, string, error) {
			if message != "" {
				return "", "", errors.New(message)
			}
			return prompt(methods)
		}
	}
	return LoginInteractive(ctx, Config{API: apiBase, Web: webOrigin}, email, password, factors, output, warnings)
}

func LoginInteractive(ctx context.Context, cfg Config, email, password string, factors LoginFactors, output, warnings io.Writer) (_ *Session, resultErr error) {
	if output == nil {
		output = io.Discard
	}
	if warnings == nil {
		warnings = io.Discard
	}
	client := api.New(cfg.API, cfg.Web)
	client.SetClientType(cfg.Client)

	params, err := client.OpaqueParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch opaque parameters: %w", err)
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
		return nil, err
	}

	auth := opaque.NewStore()
	keys := vault.NewStore(auth)
	defer func() {
		if resultErr != nil {
			keys.LockAll()
			client.Close()
		}
	}()

	op, err := prepareLogin(ctx, client, auth, pinned, email, password)
	if err != nil {
		return nil, err
	}
	defer auth.Abandon(op.id)
	grant, err := client.LoginComplete(ctx, op.challengeID, op.ke3, op.proof)
	if err != nil {
		return nil, fmt.Errorf("login complete: %w", classify(err))
	}
	if grant.TwoFactor != nil {
		if grant.AccountID != op.account {
			return nil, errors.New("verification belongs to another account")
		}
		if grant, err = solveTwoFactor(ctx, client, grant.TwoFactor, factors); err != nil {
			return nil, err
		}
	}
	if err := usableGrant(grant); err != nil {
		return nil, err
	}
	if grant.AccessToken == "" || grant.AccountID != op.account {
		return nil, fmt.Errorf("login complete: unexpected server response")
	}
	client.Adopt(grant)
	fmt.Fprintln(output, "Signed in.")

	keyList, err := client.ListMyKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list account keys: %w", err)
	}
	if _, err := auth.CompleteLoginUnlock(op.id, op.account,
		base64.StdEncoding.EncodeToString(grant.WrappedMasterKey),
		base64.StdEncoding.EncodeToString(grant.MasterKeyID)); err != nil {
		return nil, fmt.Errorf("unlock mailbox key: %w", err)
	}
	mailbox, accountKeys, err := export.UnlockAccountKeys(keys, op.account, keyList, func(set vault.KeySet) error {
		return keys.OpenFromOpaque(op.account, set)
	})
	if err != nil {
		return nil, fmt.Errorf("unlock mailbox key: %w", err)
	}
	printKeys(output, warnings, accountKeys)
	productKeys := verifyProductKeys(ctx, client, keys, op.account)
	if productKeys.Problem != nil {
		fmt.Fprintln(warnings, "warning: account keys did not verify:", productKeys.Problem)
	}

	pub, fingerprint, _, err := keys.PublicKey(op.account)
	if err != nil {
		return nil, err
	}
	fp, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, err
	}
	return &Session{
		PublicKeyArmored: pub, Fingerprint: fp, AccountID: op.account, ProductKeys: productKeys,
		BaseURL: strings.TrimRight(cfg.API, "/"),
		client:  client, store: keys, mailbox: mailbox, keys: accountKeys,
	}, nil
}

func usableGrant(grant api.LoginSessionGrant) error {
	if grant.Staged || grant.Scope == "migration_stage" || grant.Scope == "migration_finalize" {
		return ErrUpgradeRequired
	}
	if grant.Scope != "" && grant.Scope != "login" {
		return fmt.Errorf("%w: sign-in returned a %q session", ErrUpgradeRequired, grant.Scope)
	}
	return nil
}

type browserError struct{ error }

func (e *browserError) Unwrap() error { return e.error }

type operation struct {
	id, account, challengeID, proof string
	ke3                             []byte
}

func prepareLogin(ctx context.Context, client *api.Client, auth *opaque.Store, pinned opaque.Params, email, password string) (_ *operation, resultErr error) {
	login, err := auth.StartLogin(password, pinned)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			auth.Abandon(login.OperationID)
		}
	}()
	ke1, err := base64.StdEncoding.DecodeString(login.Message)
	if err != nil {
		return nil, err
	}

	init, err := client.LoginInit(ctx, email, ke1)
	if err != nil {
		return nil, fmt.Errorf("login init: %w", classify(err))
	}
	if init.AccountID == "" || len(init.KE2) == 0 {
		return nil, ErrWrongPassword
	}
	finished, err := auth.FinishLogin(login.OperationID, init.AccountID, base64.StdEncoding.EncodeToString(init.KE2), false)
	if err != nil {
		return nil, because(ErrWrongPassword, err)
	}
	ke3, err := base64.StdEncoding.DecodeString(finished.KE3)
	if err != nil {
		return nil, err
	}

	proof, err := solveLoginProof(ctx, init.ProofChallenge)
	if err != nil {
		return nil, err
	}
	return &operation{id: login.OperationID, account: init.AccountID, challengeID: init.ChallengeID, ke3: ke3, proof: proof}, nil
}

func printKeys(output, warnings io.Writer, keys []export.AccountKey) {
	unlocked := 0
	for _, k := range keys {
		if k.UnlockError == "" {
			unlocked++
			continue
		}
		fmt.Fprintf(warnings, "warning: key version %d (%s) could not be unlocked: %s\n", k.Version, k.Fingerprint, k.UnlockError)
	}
	if len(keys) == 1 {
		fmt.Fprintln(output, "Unlocked your key.")
		return
	}
	fmt.Fprintf(output, "Unlocked %d of %d keys.\n", unlocked, len(keys))
}
