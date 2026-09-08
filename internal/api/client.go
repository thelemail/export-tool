package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxAttempts = 4
	defaultBackoff     = time.Second
	maxBackoff         = 30 * time.Second
)

type Client struct {
	base      string
	webOrigin string
	http      *http.Client
	token     string
	accountID string

	MaxAttempts int
	Backoff     time.Duration
}

func New(base, webOrigin string) *Client {
	return &Client{
		base:        strings.TrimRight(base, "/"),
		webOrigin:   webOrigin,
		http:        &http.Client{Timeout: 120 * time.Second},
		MaxAttempts: defaultMaxAttempts,
		Backoff:     defaultBackoff,
	}
}

func (c *Client) SetSession(token, accountID string) {
	c.token = token
	c.accountID = accountID
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = raw
	}
	return c.attempt(ctx, func() error {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
		if err != nil {
			return err
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		if c.accountID != "" {
			req.Header.Set("X-Account-Id", c.accountID)
		}
		if c.webOrigin != "" {
			req.Header.Set("Origin", c.webOrigin)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return &TransportError{Err: scrub(err)}
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &HTTPError{Status: resp.StatusCode, Body: string(raw), RetryAfter: retryAfter(resp)}
		}
		if out != nil && len(raw) > 0 {
			return json.Unmarshal(raw, out)
		}
		return nil
	})
}

func (c *Client) GetBlob(ctx context.Context, url string) ([]byte, error) {
	var body []byte
	err := c.attempt(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return &TransportError{Err: scrub(err)}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return &HTTPError{Status: resp.StatusCode, Body: string(b), RetryAfter: retryAfter(resp)}
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return &TransportError{Err: scrub(err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (c *Client) attempt(ctx context.Context, fn func() error) error {
	attempts := c.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	base := c.Backoff
	if base <= 0 {
		base = defaultBackoff
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			if werr := wait(ctx, backoffFor(base, i, err)); werr != nil {
				return werr
			}
		}
		err = fn()
		if err == nil || !Retryable(err) {
			return err
		}
	}
	return err
}

func backoffFor(base time.Duration, attempt int, err error) time.Duration {
	var he *HTTPError
	if errors.As(err, &he) && he.RetryAfter > 0 {
		if he.RetryAfter > maxBackoff {
			return maxBackoff
		}
		return he.RetryAfter
	}
	d := base << (attempt - 1)
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if i := strings.Index(ue.URL, "?"); i >= 0 {
			return &url.Error{Op: ue.Op, URL: ue.URL[:i], Err: ue.Err}
		}
	}
	return err
}

type TransportError struct {
	Err error
}

func (e *TransportError) Error() string { return e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

type HTTPError struct {
	Status     int
	Body       string
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string { return fmt.Sprintf("http %d: %s", e.Status, e.Body) }

func (e *HTTPError) Retryable() bool {
	return e.Status == http.StatusRequestTimeout ||
		e.Status == http.StatusTooManyRequests ||
		e.Status >= 500
}

func Retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return true
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Retryable()
	}
	return false
}

func IsExpiredPointer(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false
	}
	return he.Status == http.StatusForbidden || he.Status == http.StatusNotFound
}
