package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/thelemail/export-tool/internal/api"
)

func TestSecondFactorRetryWithEnrolledBackupCode(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var input api.TwoFactorVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.PendingToken != "pending" {
			t.Error("missing sign-in challenge")
		}
		switch r.URL.Path {
		case "/v1/auth/2fa/totp/verify":
			w.WriteHeader(http.StatusUnauthorized)
		case "/v1/auth/2fa/backup-code/verify":
			if input.Code != "backup" {
				t.Errorf("unexpected backup code %q", input.Code)
			}
			_ = json.NewEncoder(w).Encode(api.LoginSessionGrant{AccountID: "account", AccessToken: "token", Scope: "login"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ch := &api.TwoFactorChallenge{Methods: []string{"totp", "backupCode"}, PendingToken: "pending", ExpiresInSeconds: 60}
	prompts := 0
	factors := LoginFactors{Prompt: func(_ context.Context, methods []string, message string) (string, string, error) {
		prompts++
		if !slices.Equal(ch.Methods, methods) {
			t.Fatal("wrong offered methods")
		}
		if prompts == 1 && message == "" {
			return "totp", "incorrect", nil
		}
		if prompts == 2 && message != "" {
			return "backupCode", " backup ", nil
		}
		t.Fatalf("unexpected prompt %d", prompts)
		return "", "", nil
	}}
	grant, err := solveTwoFactor(t.Context(), api.New(server.URL, ""), ch, factors)
	if err != nil || grant.Scope != "login" || prompts != 2 || requests != 2 {
		t.Fatalf("grant: %+v, %v", grant, err)
	}
	factors.Prompt = func(context.Context, []string, string) (string, string, error) { return "webauthn", "", nil }
	if _, err = solveTwoFactor(t.Context(), api.New(server.URL, ""), ch, factors); err == nil || requests != 2 {
		t.Fatal("accepted an unenrolled method")
	}
}

func TestPasskeyVerifiesTheFirstLoginsChallenge(t *testing.T) {
	var inits, verifies int
	options := `{"challenge":"Y2g","rpId":"thelemail.test"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Pending    string          `json:"pendingToken"`
			Credential json.RawMessage `json:"credential"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Pending != "pending" {
			t.Errorf("%s used pending token %q", r.URL.Path, body.Pending)
		}
		switch r.URL.Path {
		case "/v1/auth/2fa/webauthn/init":
			inits++
			_, _ = w.Write([]byte(`{"publicKey":` + options + `}`))
		case "/v1/auth/2fa/webauthn/verify":
			verifies++
			if string(body.Credential) != `{"id":"cred"}` {
				t.Errorf("credential = %s", body.Credential)
			}
			_ = json.NewEncoder(w).Encode(api.LoginSessionGrant{AccountID: "account", AccessToken: "token", Scope: "login"})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ch := &api.TwoFactorChallenge{Methods: []string{"webauthn"}, PendingToken: "pending", ExpiresInSeconds: 120}
	attempts := 0
	factors := LoginFactors{
		Prompt: func(context.Context, []string, string) (string, string, error) { return "webauthn", "", nil },
		Passkey: func(_ context.Context, req PasskeyRequest) (json.RawMessage, error) {
			attempts++
			if string(req.Options) != options || time.Until(req.Expires) <= 0 || time.Until(req.Expires) > 2*time.Minute {
				t.Errorf("passkey request = %s until %v", req.Options, req.Expires)
			}
			if attempts == 1 {
				return nil, errors.New("dismissed")
			}
			return json.RawMessage(`{"id":"cred"}`), nil
		},
	}
	grant, err := solveTwoFactor(t.Context(), api.New(server.URL, ""), ch, factors)
	if err != nil || grant.AccessToken != "token" {
		t.Fatalf("grant %+v, %v", grant, err)
	}
	if inits != 2 || verifies != 1 || attempts != 2 {
		t.Fatalf("inits %d verifies %d attempts %d", inits, verifies, attempts)
	}
}

func TestStagedAccountsMustUpgradeFirst(t *testing.T) {
	for _, g := range []api.LoginSessionGrant{
		{Staged: true, Scope: "login"},
		{Scope: "migration_stage"},
		{Scope: "migration_finalize"},
		{Scope: "recovery"},
	} {
		if err := usableGrant(g); !errors.Is(err, ErrUpgradeRequired) {
			t.Fatalf("grant %+v: err = %v", g, err)
		}
	}
	if err := usableGrant(api.LoginSessionGrant{Scope: "login"}); err != nil {
		t.Fatal(err)
	}
	if err := usableGrant(api.LoginSessionGrant{}); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformErrorsBecomeSignInProblems(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
		wait   time.Duration
	}{
		{http.StatusUnauthorized, `{"error":{"code":"invalid_credentials"}}`, ErrWrongPassword, 0},
		{http.StatusTooManyRequests, `{"error":{"code":"rate_limited","retryAfterSeconds":900}}`, ErrRateLimited, 15 * time.Minute},
		{http.StatusUnprocessableEntity, `{"error":{"code":"proof_expired"}}`, ErrProofFailed, 0},
		{http.StatusForbidden, `{"error":{"code":"account_suspended"}}`, ErrSuspended, 0},
	}
	for _, c := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		_, err := api.New(server.URL, "").LoginComplete(t.Context(), "ch", nil, "")
		server.Close()
		got := classify(err)
		if !errors.Is(got, c.want) {
			t.Fatalf("%d: %v, want %v", c.status, got, c.want)
		}
		var he *api.HTTPError
		if !errors.As(got, &he) {
			t.Fatalf("%d: platform detail lost", c.status)
		}
		var wait *WaitError
		if c.wait > 0 && (!errors.As(got, &wait) || wait.Wait != c.wait) {
			t.Fatalf("%d: wait = %+v", c.status, wait)
		}
	}
}
