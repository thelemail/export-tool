package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(srv *httptest.Server) *Client {
	c := New(srv.URL, "http://localhost")
	c.MaxAttempts = 3
	c.Backoff = time.Millisecond
	return c
}

func TestGetBlobRetriesServerErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	body, err := testClient(srv).GetBlob(context.Background(), "/blob")
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	if string(body) != "payload" {
		t.Fatalf("body = %q", body)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestGetBlobDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := testClient(srv).GetBlob(context.Background(), "/blob")
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusForbidden {
		t.Fatalf("err = %v", err)
	}
	if Retryable(err) {
		t.Fatal("403 was treated as retryable")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestDoRetriesAndReplaysTheRequestBody(t *testing.T) {
	var calls atomic.Int32
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		seen = append(seen, string(buf))
		if calls.Add(1) < 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"sessionId":"s"}`))
	}))
	defer srv.Close()

	var out ExportHeartbeatResponse
	if err := testClient(srv).do(context.Background(), http.MethodPost, "/x", map[string]string{"a": "b"}, &out); err != nil {
		t.Fatalf("do: %v", err)
	}
	if out.SessionID != "s" {
		t.Fatalf("sessionId = %q", out.SessionID)
	}
	if len(seen) != 2 || seen[0] != seen[1] || seen[0] != `{"a":"b"}` {
		t.Fatalf("bodies = %q", seen)
	}
}

func TestDoGivesUpAfterMaxAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	err := testClient(srv).do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !Retryable(err) {
		t.Fatalf("err = %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestRetryStopsWhenTheContextIsCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	c := testClient(srv)
	c.Backoff = time.Second
	cancel()

	if err := c.do(ctx, http.MethodGet, "/x", nil, nil); err == nil {
		t.Fatal("expected an error")
	}
}

func TestTransportErrorsAreRetryable(t *testing.T) {
	c := New("http://127.0.0.1:1", "")
	c.MaxAttempts = 2
	c.Backoff = time.Millisecond
	err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)
	if err == nil || !Retryable(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetBlobSendsTheSessionToTheAPI(t *testing.T) {
	var auth, account, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, account, path = r.Header.Get("Authorization"), r.Header.Get("X-Account-Id"), r.URL.Path
		_, _ = w.Write([]byte("ciphertext"))
	}))
	defer srv.Close()
	c := testClient(srv)
	c.SetSession("tok", "acct")
	body, err := c.GetBlob(context.Background(), "/v1/messages/m1/body")
	if err != nil || string(body) != "ciphertext" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
	if auth != "Bearer tok" || account != "acct" || path != "/v1/messages/m1/body" {
		t.Fatalf("auth = %q, account = %q, path = %q", auth, account, path)
	}
}

func TestGetBlobRefusesPathsOffTheAPI(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()
	c := testClient(srv)
	c.SetSession("tok", "acct")
	for _, p := range []string{
		"",
		"v1/messages/m1/body",
		"https://elsewhere.test/v1/messages/m1/body",
		"//elsewhere.test/v1/messages/m1/body",
		"/\\elsewhere.test/v1",
		"@elsewhere.test/v1",
	} {
		if _, err := c.GetBlob(context.Background(), p); !errors.Is(err, ErrBlobPath) {
			t.Fatalf("%q: err = %v", p, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestHTTPErrorsCollapseLongBodies(t *testing.T) {
	body := "<?xml version=\"1.0\"?>\n<Error>\n  <Code>NoSuchKey</Code>\n</Error>"
	err := &HTTPError{Status: 404, Body: body}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("error spans multiple lines: %q", err.Error())
	}
	long := &HTTPError{Status: 500, Body: strings.Repeat("x", 500)}
	if len(long.Error()) > 240 {
		t.Fatalf("error is %d chars", len(long.Error()))
	}
}

func TestListMyKeysReadsTheKeyHistory(t *testing.T) {
	var auth, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, path = r.Header.Get("Authorization"), r.URL.Path
		_, _ = w.Write([]byte(`{"currentVersion":2,"keys":[` +
			`{"keyVersion":2,"keyFingerprint":"aa","keyAlgorithm":"openpgp-curve25519-v6","publicKeyArmored":"pub2","encryptedPrivateKey":"priv2","isCurrent":true,"activatedAt":"2026-10-01T10:00:00Z","transitions":[{"previousKeyFingerprint":"bb","signature":"c2lnbmF0dXJl"}]},` +
			`{"keyVersion":1,"keyFingerprint":"bb","keyAlgorithm":"openpgp-ed25519","publicKeyArmored":"pub1","encryptedPrivateKey":"priv1","isCurrent":false,"activatedAt":"2026-06-03T21:35:27Z","retiredAt":"2026-10-01T10:00:00Z","transitions":[]}]}`))
	}))
	defer srv.Close()

	c := testClient(srv)
	c.SetSession("tok", "acct")
	out, err := c.ListMyKeys(context.Background())
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	if path != "/v1/me/keys" || auth != "Bearer tok" {
		t.Fatalf("path = %q, auth = %q", path, auth)
	}
	if out.CurrentVersion != 2 || len(out.Keys) != 2 {
		t.Fatalf("out = %+v", out)
	}
	cur, old := out.Keys[0], out.Keys[1]
	if !cur.IsCurrent || cur.KeyVersion != 2 || cur.EncryptedPrivateKey != "priv2" || cur.RetiredAt != nil {
		t.Fatalf("current = %+v", cur)
	}
	retired := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	if old.IsCurrent || old.KeyFingerprint != "bb" || old.PublicKeyArmored != "pub1" || old.RetiredAt == nil || !old.RetiredAt.Equal(retired) {
		t.Fatalf("history = %+v", old)
	}
}
