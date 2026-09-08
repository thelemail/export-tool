package api

import (
	"context"
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

	body, err := testClient(srv).GetBlob(context.Background(), srv.URL+"/blob")
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

	_, err := testClient(srv).GetBlob(context.Background(), srv.URL+"/blob")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsExpiredPointer(err) {
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

func TestTransportErrorsDropPresignedQueryStrings(t *testing.T) {
	c := New("http://127.0.0.1:1", "")
	c.MaxAttempts = 1
	_, err := c.GetBlob(context.Background(), "http://127.0.0.1:1/blob/x.pgp?X-Amz-Signature=deadbeef&X-Amz-Expires=60")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "X-Amz-Signature") {
		t.Fatalf("error leaks the presigned query: %v", err)
	}
	if !strings.Contains(err.Error(), "/blob/x.pgp") {
		t.Fatalf("error lost the object path: %v", err)
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
