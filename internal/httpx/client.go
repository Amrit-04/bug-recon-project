package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/scoutr/scoutr/internal/scope"
	"golang.org/x/time/rate"
)

// Client is a scope-enforcing, rate-limited HTTP client.
// All requests are checked against scope before being sent.
// Out-of-scope requests are blocked, including redirects.
type Client struct {
	httpClient  *http.Client
	scope       *scope.Scope
	rateLimiter *RateLimiter
	maxBodySize int64
	dryRun      bool
}

// Config holds configuration for creating a Client.
type Config struct {
	Scope         *scope.Scope
	Timeout       time.Duration
	MaxBodySize   int64
	GlobalRate    float64 // requests per second (global)
	PerHostRate   float64 // requests per second per host
	DryRun        bool
	UserAgent     string
	CustomHeaders map[string]string
}

// New creates a new scope-enforcing HTTP client.
func New(cfg Config) *Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}

	rateLimiter := NewRateLimiter(cfg.GlobalRate, cfg.PerHostRate)

	// Wrap the transport with scope enforcement and rate limiting
	scopedTransport := &ScopedTransport{
		base:        transport,
		scope:       cfg.Scope,
		rateLimiter: rateLimiter,
		maxBodySize: cfg.MaxBodySize,
		dryRun:      cfg.DryRun,
		userAgent:   cfg.UserAgent,
		headers:     cfg.CustomHeaders,
	}

	httpClient := &http.Client{
		Transport: scopedTransport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Block redirects to out-of-scope hosts
			if !cfg.Scope.IsURLInScope(req.URL.String()) {
				return fmt.Errorf("redirect to out-of-scope host: %s", req.URL.Host)
			}
			// Limit redirect chain to 10
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Client{
		httpClient:  httpClient,
		scope:       cfg.Scope,
		rateLimiter: rateLimiter,
		maxBodySize: cfg.MaxBodySize,
		dryRun:      cfg.DryRun,
	}
}

// Get performs a GET request with scope and rate limit enforcement.
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}

// Head performs a HEAD request with scope and rate limit enforcement.
func (c *Client) Head(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}

// Do executes an HTTP request with scope and rate limit enforcement.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

// ScopedTransport is an http.RoundTripper that enforces scope and rate limits.
type ScopedTransport struct {
	base        http.RoundTripper
	scope       *scope.Scope
	rateLimiter *RateLimiter
	maxBodySize int64
	dryRun      bool
	userAgent   string
	headers     map[string]string
}

// RoundTrip implements http.RoundTripper with scope and rate limit checks.
func (t *ScopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check scope before sending
	if !t.scope.IsURLInScope(req.URL.String()) {
		return nil, fmt.Errorf("blocked: %s is out of scope", req.URL.String())
	}

	// Wait for rate limiter (both global and per-host)
	if err := t.rateLimiter.Wait(req.Context(), req.URL.Host); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	// Set User-Agent if not already set
	if req.Header.Get("User-Agent") == "" && t.userAgent != "" {
		req.Header.Set("User-Agent", t.userAgent)
	}

	// Apply custom headers
	for k, v := range t.headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	// Dry run: log and return a fake success
	if t.dryRun {
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK (dry run)",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       io.NopCloser(&emptyReader{}),
			Request:    req,
		}, nil
	}

	// Execute the request
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Wrap the response body with a size limiter
	if resp.Body != nil {
		resp.Body = &limitedBody{
			body:  resp.Body,
			limit: t.maxBodySize,
		}
	}

	return resp, nil
}

// limitedBody wraps an io.ReadCloser with a size limit.
type limitedBody struct {
	body  io.ReadCloser
	limit int64
	read  int64
	mu    sync.Mutex
}

func (lb *limitedBody) Read(p []byte) (int, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if lb.read >= lb.limit {
		return 0, io.EOF
	}

	// Adjust read size to not exceed limit
	maxRead := lb.limit - lb.read
	if int64(len(p)) > maxRead {
		p = p[:maxRead]
	}

	n, err := lb.body.Read(p)
	lb.read += int64(n)
	return n, err
}

func (lb *limitedBody) Close() error {
	return lb.body.Close()
}

// emptyReader is an empty io.Reader for dry run responses.
type emptyReader struct{}

func (e *emptyReader) Read(p []byte) (int, error) {
	return 0, io.EOF
}

// RateLimiter manages global and per-host rate limits.
type RateLimiter struct {
	global     *rate.Limiter
	perHost    *rate.Limiter // Template for per-host limiters
	hostLimits sync.Map      // map[string]*rate.Limiter
}

// NewRateLimiter creates a new rate limiter with global and per-host limits.
func NewRateLimiter(globalRate, perHostRate float64) *RateLimiter {
	var global, perHost *rate.Limiter

	if globalRate > 0 {
		global = rate.NewLimiter(rate.Limit(globalRate), int(globalRate)+1)
	}

	if perHostRate > 0 {
		perHost = rate.NewLimiter(rate.Limit(perHostRate), int(perHostRate)+1)
	}

	return &RateLimiter{
		global:  global,
		perHost: perHost,
	}
}

// Wait blocks until the request is allowed by both global and per-host rate limits.
func (rl *RateLimiter) Wait(ctx context.Context, host string) error {
	// Global rate limit
	if rl.global != nil {
		if err := rl.global.Wait(ctx); err != nil {
			return err
		}
	}

	// Per-host rate limit
	if rl.perHost != nil {
		limiter := rl.getHostLimiter(host)
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}

	return nil
}

// getHostLimiter retrieves or creates a rate limiter for a specific host.
func (rl *RateLimiter) getHostLimiter(host string) *rate.Limiter {
	if v, ok := rl.hostLimits.Load(host); ok {
		return v.(*rate.Limiter)
	}

	// Create a new limiter with the same rate as the template
	limiter := rate.NewLimiter(rl.perHost.Limit(), rl.perHost.Burst())
	actual, _ := rl.hostLimits.LoadOrStore(host, limiter)
	return actual.(*rate.Limiter)
}
