package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var (
	ErrSessionEnded = errors.New("the Thelemail session ended")
	ErrOutsideAPI   = errors.New("request is outside the mailbox API")
)

const (
	refreshAhead    = 10 * time.Second
	refreshAttempts = 3
)

func (c *Client) Adopt(g LoginSessionGrant) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setGrant(g)
}

func (c *Client) setGrant(g LoginSessionGrant) {
	c.token, c.accountID, c.csrf = g.AccessToken, g.AccountID, g.CSRFToken
	c.ended = false
	c.expires = time.Time{}
	if g.ExpiresInSeconds > 0 {
		c.expires = time.Now().Add(time.Duration(g.ExpiresInSeconds) * time.Second)
	}
}

func (c *Client) current() (token string, due, ended bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token, c.token != "" && !c.expires.IsZero() && time.Until(c.expires) < refreshAhead, c.ended
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	base, err := url.Parse(c.base)
	if err != nil || req.URL.Scheme != base.Scheme || req.URL.Host != base.Host || req.URL.User != nil || (req.Host != "" && req.Host != base.Host) {
		return nil, ErrOutsideAPI
	}
	ctx := req.Context()
	token, due, ended := c.current()
	if ended {
		return nil, ErrSessionEnded
	}
	if due {
		if err := c.renew(ctx, token); err != nil {
			return nil, err
		}
		token, _, _ = c.current()
	}
	resp, err := c.send(req, req.Body)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || token == "" {
		return resp, err
	}
	body, replayable := replayBody(req)
	if !replayable {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if err := c.renew(ctx, token); err != nil {
		return nil, err
	}
	return c.send(req, body)
}

func replayBody(req *http.Request) (io.ReadCloser, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return req.Body, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	return body, err == nil
}

func (c *Client) send(req *http.Request, body io.ReadCloser) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Body = body
	c.mu.Lock()
	c.setHeaders(out)
	c.mu.Unlock()
	return c.http.Do(out)
}

func (c *Client) setHeaders(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("X-Account-Id", c.accountID)
	}
	if c.webOrigin != "" {
		req.Header.Set("Origin", c.webOrigin)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.clientType != "" {
		req.Header.Set("X-Client", c.clientType)
	}
}

func (c *Client) renew(ctx context.Context, stale string) error {
	c.renewing.Lock()
	defer c.renewing.Unlock()
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	if token == "" {
		return ErrSessionEnded
	}
	if token != stale {
		return nil
	}
	base := c.Backoff
	if base <= 0 {
		base = defaultBackoff
	}
	var err error
	for attempt := range refreshAttempts {
		if attempt > 0 {
			if werr := wait(ctx, backoffFor(base, attempt, err)); werr != nil {
				return werr
			}
		}
		if err = c.refresh(ctx); err == nil || !Retryable(err) {
			return err
		}
	}
	return fmt.Errorf("renew the Thelemail session: %w", err)
}

func (c *Client) refresh(ctx context.Context) error {
	req, err := c.request(ctx, http.MethodPost, "/v1/auth/refresh", nil)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.setHeaders(req)
	account := c.accountID
	c.mu.Unlock()
	resp, err := c.http.Do(req)
	if err != nil {
		return sendError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		he := newHTTPError(resp, raw)
		if he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden {
			c.end()
			return fmt.Errorf("%w: %w", ErrSessionEnded, he)
		}
		return he
	}
	var g LoginSessionGrant
	if err := json.Unmarshal(raw, &g); err != nil {
		return &TransportError{Err: err}
	}
	if g.AccountID != account || g.AccessToken == "" || g.ExpiresInSeconds <= 0 {
		c.end()
		return fmt.Errorf("%w: refresh returned an invalid mailbox session", ErrSessionEnded)
	}
	c.mu.Lock()
	c.setGrant(g)
	c.mu.Unlock()
	return nil
}

func (c *Client) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setGrant(LoginSessionGrant{})
	c.ended = true
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if req, err := c.request(ctx, http.MethodPost, "/v1/auth/logout", nil); err == nil {
			c.setHeaders(req)
			if resp, err := c.http.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
	c.setGrant(LoginSessionGrant{})
	c.http.CloseIdleConnections()
}
