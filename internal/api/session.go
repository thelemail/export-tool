package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

func (c *Client) Adopt(g LoginSessionGrant) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setGrant(g)
}

func (c *Client) setGrant(g LoginSessionGrant) {
	c.token, c.accountID, c.csrf = g.AccessToken, g.AccountID, g.CSRFToken
	c.expires = time.Time{}
	if g.ExpiresInSeconds > 0 {
		c.expires = time.Now().Add(time.Duration(g.ExpiresInSeconds) * time.Second)
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	base, err := url.Parse(c.base)
	if err != nil || req.URL.Scheme != base.Scheme || req.URL.Host != base.Host || req.URL.User != nil || (req.Host != "" && req.Host != base.Host) {
		return nil, errors.New("request is outside the mailbox API")
	}
	req = req.Clone(req.Context())
	c.mu.Lock()
	if !c.expires.IsZero() && time.Until(c.expires) < 10*time.Second {
		if err := c.refresh(req.Context()); err != nil {
			c.mu.Unlock()
			return nil, err
		}
	}
	c.setHeaders(req)
	c.mu.Unlock()
	return c.http.Do(req)
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
}

func (c *Client) refresh(ctx context.Context) error {
	req, err := c.request(ctx, http.MethodPost, "/v1/auth/refresh", nil)
	if err != nil {
		return err
	}
	c.setHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{Status: resp.StatusCode, RetryAfter: retryAfter(resp)}
	}
	var g LoginSessionGrant
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&g); err != nil {
		return err
	}
	if g.AccountID != c.accountID || g.AccessToken == "" || g.ExpiresInSeconds <= 0 {
		return errors.New("refresh returned an invalid mailbox session")
	}
	c.setGrant(g)
	return nil
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
