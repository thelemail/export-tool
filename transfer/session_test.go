package transfer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

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
	grant, err := solveTwoFactor(t.Context(), api.New(server.URL, ""), ch, factors, nil)
	if err != nil || grant.Scope != "login" || prompts != 2 || requests != 2 {
		t.Fatalf("grant: %+v, %v", grant, err)
	}
	factors.Prompt = func(context.Context, []string, string) (string, string, error) { return "webauthn", "", nil }
	if _, err = solveTwoFactor(t.Context(), api.New(server.URL, ""), ch, factors, nil); err == nil || requests != 2 {
		t.Fatal("accepted an unenrolled method")
	}
}
