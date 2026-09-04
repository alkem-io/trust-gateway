// Package upstream performs the SDK's PerformHttp effects against the trust service. In fixtures
// mode it rewrites the SDK-emitted host (a hardcoded Cleverbase host) to the mock upstream base.
package upstream

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client performs HTTP effects, optionally rewriting the host (fixtures mode).
type Client struct {
	HTTP      *http.Client
	RewriteTo string // scheme://host to rewrite the SDK host to; "" disables rewriting (live)
}

// New builds a client; rewriteTo is the mock base in fixtures mode (or "" for live).
func New(rewriteTo string) *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}, RewriteTo: rewriteTo}
}

// Rewrite replaces the scheme+host of rawURL with RewriteTo's (keeping path+query). Also used for
// the redirect URLs the service hands back to the frontend so the browser hits the mock in fixtures.
func (c *Client) Rewrite(rawURL string) string {
	if c.RewriteTo == "" {
		return rawURL
	}
	in, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	base, err := url.Parse(c.RewriteTo)
	if err != nil || base.Host == "" {
		return rawURL
	}
	in.Scheme = base.Scheme
	in.Host = base.Host
	return in.String()
}

// Do performs one request and returns the response status code + body. The request is bound to the
// caller's context (threaded from the HTTP handler through the flow engine), so a client disconnect or
// server shutdown cancels an in-flight call; the http.Client.Timeout still bounds each call.
func (c *Client) Do(ctx context.Context, method, rawURL string, headers [][2]string, body []byte) (int, []byte, error) {
	target := c.Rewrite(rawURL)
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		return 0, nil, err
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}
