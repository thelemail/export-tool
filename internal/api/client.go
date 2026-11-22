package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxAttempts = 4
	defaultBackoff     = time.Second
	maxBackoff         = 30 * time.Second
)

type Client struct {
	base       string
	webOrigin  string
	clientType string
	http       *http.Client
	mu         sync.Mutex
	renewing   sync.Mutex
	ended      bool
	expires    time.Time
	csrf       string
	token      string
	accountID  string

	MaxAttempts int
	Backoff     time.Duration
}

func New(base, webOrigin string) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		base:        strings.TrimRight(base, "/"),
		webOrigin:   webOrigin,
		http:        &http.Client{Timeout: 120 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		MaxAttempts: defaultMaxAttempts,
		Backoff:     defaultBackoff,
	}
}

func (c *Client) SetClientType(clientType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientType = clientType
}

func (c *Client) SetSession(token, accountID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.accountID = accountID
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	return c.call(ctx, method, path, body, out, true)
}

func (c *Client) doOnce(ctx context.Context, method, path string, body, out any) error {
	return c.call(ctx, method, path, body, out, false)
}

func (c *Client) call(ctx context.Context, method, path string, body, out any, retry bool) error {
	var payload []byte
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = raw
	}
	run := c.attempt
	if !retry {
		run = func(_ context.Context, fn func() error) error { return fn() }
	}
	return run(ctx, func() error {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := c.request(ctx, method, path, reader)
		if err != nil {
			return err
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			return sendError(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return newHTTPError(resp, raw)
		}
		if out != nil && len(raw) > 0 {
			return json.Unmarshal(raw, out)
		}
		return nil
	})
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	return req, nil
}

var ErrBlobPath = errors.New("api: blob pointer is not a path on this API")

func (c *Client) checkBlobPath(path string) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "\\") {
		return fmt.Errorf("%w: %q", ErrBlobPath, path)
	}
	base, err := url.Parse(c.base)
	if err != nil {
		return err
	}
	full, err := url.Parse(c.base + path)
	if err != nil || full.Scheme != base.Scheme || full.Host != base.Host {
		return fmt.Errorf("%w: %q", ErrBlobPath, path)
	}
	return nil
}

func (c *Client) GetBlob(ctx context.Context, path string) ([]byte, error) {
	if err := c.checkBlobPath(path); err != nil {
		return nil, err
	}
	var body []byte
	err := c.attempt(ctx, func() error {
		req, err := c.request(ctx, http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		resp, err := c.Do(req)
		if err != nil {
			return sendError(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return newHTTPError(resp, b)
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return &TransportError{Err: err}
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

func sendError(err error) error {
	var he *HTTPError
	if errors.As(err, &he) || errors.Is(err, ErrSessionEnded) || errors.Is(err, ErrOutsideAPI) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &TransportError{Err: err}
}

type TransportError struct {
	Err error
}

func (e *TransportError) Error() string { return e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

type HTTPError struct {
	Status     int
	Code       string
	Message    string
	Body       string
	RetryAfter time.Duration
}

func newHTTPError(resp *http.Response, body []byte) *HTTPError {
	e := &HTTPError{Status: resp.StatusCode, Body: string(body), RetryAfter: retryAfter(resp)}
	var env struct {
		Error struct {
			Code              string `json:"code"`
			Message           string `json:"message"`
			RetryAfterSeconds int64  `json:"retryAfterSeconds"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil {
		e.Code, e.Message = env.Error.Code, env.Error.Message
		if e.RetryAfter == 0 && env.Error.RetryAfterSeconds > 0 {
			e.RetryAfter = time.Duration(env.Error.RetryAfterSeconds) * time.Second
		}
	}
	return e
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("http %d: %s", e.Status, summarizeBody(e.Body))
}

func summarizeBody(body string) string {
	const maxBodyChars = 200
	flat := strings.Join(strings.Fields(body), " ")
	if len(flat) > maxBodyChars {
		return flat[:maxBodyChars] + "..."
	}
	return flat
}

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
