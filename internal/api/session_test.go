package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
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
