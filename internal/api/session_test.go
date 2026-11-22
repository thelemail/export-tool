package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLongTransferRefreshesOnceAcrossWorkers(t *testing.T) {
	var refreshes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/login/complete", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "refresh", Value: "fixture", Path: "/v1/auth"})
		_ = json.NewEncoder(w).Encode(LoginSessionGrant{AccountID: "account", AccessToken: "initial", ExpiresInSeconds: 1})
	})
	mux.HandleFunc("/v1/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		if c, err := r.Cookie("refresh"); err != nil || c.Value != "fixture" || r.Header.Get("Origin") != "http://localhost" || r.Header.Get("X-Account-Id") != "account" {
			t.Error("refresh did not use the signed-in mailbox")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(LoginSessionGrant{AccountID: "account", AccessToken: "renewed", ExpiresInSeconds: 3600})
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer renewed" {
			t.Error("stale authorization")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := testClient(srv)
	g, err := c.LoginComplete(t.Context(), "challenge", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Adopt(g)
	var workers sync.WaitGroup
	for range 3 {
		workers.Go(func() {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/messages", nil)
			if err != nil {
				t.Error(err)
				return
			}
			resp, err := c.Do(r)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
		})
	}
	workers.Wait()
	if got := refreshes.Load(); got != 1 {
		t.Fatalf("got %d refreshes", got)
	}
}

func signedIn(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := testClient(srv)
	c.Adopt(LoginSessionGrant{AccountID: "account", AccessToken: "initial", ExpiresInSeconds: 3600, CSRFToken: "csrf"})
	return c
}

func TestSingleUseAuthCallsAreSentOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := testClient(srv)
	for name, call := range map[string]func() error{
		"login init":     func() error { _, err := c.LoginInit(t.Context(), "a@b.test", []byte("ke1")); return err },
		"login complete": func() error { _, err := c.LoginComplete(t.Context(), "ch", []byte("ke3"), ""); return err },
		"totp":           func() error { _, err := c.VerifyTOTP(t.Context(), "pending", "123456"); return err },
		"backup code":    func() error { _, err := c.VerifyBackupCode(t.Context(), "pending", "code"); return err },
		"passkey":        func() error { _, err := c.VerifyPasskey(t.Context(), "pending", json.RawMessage(`{}`)); return err },
		"passkey init":   func() error { _, err := c.WebauthnLoginInit(t.Context(), "pending"); return err },
	} {
		calls.Store(0)
		if err := call(); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("%s sent %d times", name, got)
		}
	}
	calls.Store(0)
	if _, err := c.ListMyKeys(t.Context()); err == nil || calls.Load() != 3 {
		t.Fatalf("idempotent read sent %d times", calls.Load())
	}
}

func TestExpiredTokenIsRefreshedAndTheRequestReplayed(t *testing.T) {
	var refreshes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		refreshes.Add(1)
		_ = json.NewEncoder(w).Encode(LoginSessionGrant{AccountID: "account", AccessToken: "renewed", ExpiresInSeconds: 3600})
	})
	var bodies []string
	mux.HandleFunc("/v1/messages/import", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if r.Header.Get("Authorization") != "Bearer renewed" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := signedIn(t, srv)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v1/messages/import", strings.NewReader(`{"m":1}`))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || refreshes.Load() != 1 {
		t.Fatalf("status %d after %d refreshes", resp.StatusCode, refreshes.Load())
	}
	if len(bodies) != 2 || bodies[1] != `{"m":1}` {
		t.Fatalf("replayed bodies = %q", bodies)
	}
}

func TestRejectedRefreshEndsTheSession(t *testing.T) {
	var requests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := signedIn(t, srv)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/v1/me", nil)
	if _, err := c.Do(req); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("err = %v, want ErrSessionEnded", err)
	}
	if _, err := c.Do(req); !errors.Is(err, ErrSessionEnded) || requests.Load() != 1 {
		t.Fatalf("after the session ended: err = %v, %d requests", err, requests.Load())
	}
	if err := c.do(t.Context(), http.MethodGet, "/v1/me", nil, nil); !errors.Is(err, ErrSessionEnded) || Retryable(err) {
		t.Fatalf("api call after the session ended: %v", err)
	}
}

func TestTransientRefreshFailureBacksOff(t *testing.T) {
	var refreshes atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		if refreshes.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(LoginSessionGrant{AccountID: "account", AccessToken: "renewed", ExpiresInSeconds: 3600})
	})
	mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer renewed" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := signedIn(t, srv)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/v1/me", nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent || refreshes.Load() != 2 {
		t.Fatalf("resp %v err %v after %d refreshes", resp, err, refreshes.Load())
	}
}

func TestRequestsIdentifyTheClient(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := signedIn(t, srv)
	c.SetClientType("migrator")
	if err := c.do(t.Context(), http.MethodGet, "/v1/me", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-Client") != "migrator" || got.Get("Origin") != "http://localhost" || got.Get("X-CSRF-Token") != "csrf" || got.Get("Authorization") != "Bearer initial" {
		t.Fatalf("headers = %v", got)
	}
}

func TestErrorEnvelopeIsParsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"too many failed attempts, try again later","retryAfterSeconds":900}}`))
	}))
	defer srv.Close()
	c := testClient(srv)
	_, err := c.LoginComplete(t.Context(), "ch", nil, "")
	var he *HTTPError
	if !errors.As(err, &he) || he.Code != "rate_limited" || he.RetryAfter != 900*time.Second {
		t.Fatalf("err = %#v", err)
	}
}
