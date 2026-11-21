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

var errAuth = errors.New("check your email address and password. If you have an older account, sign in at auth.thelemail.com first, then try again")
var ErrIncomplete = export.ErrIncomplete

type FactorPrompt func(methods []string) (method, code string, err error)

type Session struct {
	ProductKeyWarning error
	PublicKeyArmored  string
	Fingerprint       []byte
	BaseURL           string
	AccountID         string
	client            *api.Client
	store             *vault.Store
	mailbox           *export.Vault
	keys              []export.AccountKey
}

func (s *Session) Do(req *http.Request) (*http.Response, error) { return s.client.Do(req) }

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

type LoginFactors struct {
	Prompt  func(ctx context.Context, methods []string, message string) (method, code string, err error)
	Passkey func(context.Context, BrowserLogin) (PasskeyResponse, error)
}

func solveTwoFactor(ctx context.Context, client *api.Client, ch *api.TwoFactorChallenge, factors LoginFactors, passkey func(context.Context) (api.LoginSessionGrant, error)) (api.LoginSessionGrant, error) {
	var grant api.LoginSessionGrant
	if factors.Prompt == nil || ch.PendingToken == "" {
		return grant, errors.New("a second factor is required")
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
			grant, err = passkey(ctx)
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
			return grant, errors.New("verification expired. Sign in again")
		}
		return grant, err
	}
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
	return LoginInteractive(ctx, apiBase, webOrigin, email, password, factors, output, warnings)
}

func LoginInteractive(ctx context.Context, apiBase, webOrigin, email, password string, factors LoginFactors, output, warnings io.Writer) (_ *Session, resultErr error) {
	if output == nil {
		output = io.Discard
	}
	if warnings == nil {
		warnings = io.Discard
	}
	client := api.New(apiBase, webOrigin)

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
	unlockID := op.id
	defer func() {
		if unlockID != op.id {
			auth.Abandon(unlockID)
		}
	}()
	grant, err := client.LoginComplete(ctx, op.request.ChallengeID, op.request.KE3, op.request.Proof)
	if err != nil {
		return nil, fmt.Errorf("login complete: %w", err)
	}
	if grant.TwoFactor != nil {
		if grant.AccountID != op.account {
			return nil, errors.New("verification belongs to another account")
		}
		grant, err = solveTwoFactor(ctx, client, grant.TwoFactor, factors, func(ctx context.Context) (api.LoginSessionGrant, error) {
			var grant api.LoginSessionGrant
			fresh, err := prepareLogin(ctx, client, auth, pinned, email, password)
			if err != nil {
				return grant, err
			}
			defer func() {
				if unlockID != fresh.id {
					auth.Abandon(fresh.id)
				}
			}()
			if fresh.account != op.account {
				return grant, errAuth
			}
			assertion, err := factors.Passkey(ctx, fresh.request)
			if err != nil {
				return grant, &browserError{err}
			}
			if assertion.PendingToken == "" || len(assertion.Credential) == 0 {
				return grant, errors.New("missing browser passkey response")
			}
			grant, err = client.VerifyPasskey(ctx, assertion.PendingToken, assertion.Credential)
			if err == nil {
				unlockID = fresh.id
			}
			return grant, err
		})
		if err != nil {
			return nil, err
		}
		if grant.Scope != "login" {
			return nil, errors.New("verification did not return a sign-in session. Sign in at auth.thelemail.com and retry")
		}
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
	if _, err := auth.CompleteLoginUnlock(unlockID, op.account,
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
	var refused *export.ProductKeysRefused
	var productWarning error
	switch _, err := export.VerifyProductKeys(ctx, client, keys, op.account); {
	case errors.As(err, &refused) && !refused.Enforced:
		productWarning = err
		fmt.Fprintln(warnings, "warning: account keys did not verify:", err)
	case err != nil:
		return nil, fmt.Errorf("verify account keys: %w", err)
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
		PublicKeyArmored: pub, Fingerprint: fp, AccountID: op.account, ProductKeyWarning: productWarning,
		BaseURL: strings.TrimRight(apiBase, "/"),
		client:  client, store: keys, mailbox: mailbox, keys: accountKeys,
	}, nil
}

type BrowserLogin struct {
	ChallengeID string `json:"challengeId"`
	KE3         []byte `json:"ke3"`
	Proof       string `json:"proof,omitempty"`
	AccountID   string `json:"accountId"`
}

type PasskeyResponse struct {
	PendingToken string          `json:"pendingToken"`
	Credential   json.RawMessage `json:"credential"`
}

type browserError struct{ error }

type operation struct {
	id, account string
	request     BrowserLogin
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
		return nil, fmt.Errorf("login init: %w", err)
	}
	if init.AccountID == "" || len(init.KE2) == 0 {
		return nil, errAuth
	}
	finished, err := auth.FinishLogin(login.OperationID, init.AccountID, base64.StdEncoding.EncodeToString(init.KE2), false)
	if err != nil {
		return nil, errAuth
	}
	ke3, err := base64.StdEncoding.DecodeString(finished.KE3)
	if err != nil {
		return nil, err
	}

	proof, err := solveLoginProof(ctx, init.ProofChallenge)
	if err != nil {
		return nil, err
	}
	return &operation{id: login.OperationID, account: init.AccountID, request: BrowserLogin{ChallengeID: init.ChallengeID, KE3: ke3, Proof: proof, AccountID: init.AccountID}}, nil
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
