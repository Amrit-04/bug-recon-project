// Package probe provides live host probing functionality.
package probe

import (
	"context"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

// Result represents the result of probing a single host.
type Result struct {
	Host       string `json:"host"`
	URL        string `json:"url"`
	Live       bool   `json:"live"`
	StatusCode int    `json:"status_code,omitempty"`
	Title      string `json:"title,omitempty"`
	Server     string `json:"server,omitempty"`
	ContentLen int64  `json:"content_length,omitempty"`
	Redirect   string `json:"redirect,omitempty"`
	HTTPS      bool   `json:"https"`
	Error      string `json:"error,omitempty"`
}

// Options controls the HTTP behaviour of host probing. Zero values fall back to
// conservative defaults, and every request is made through one scope-enforcing
// client so rate limits and custom headers apply to the whole probe run.
type Options struct {
	Timeout     time.Duration
	MaxBodySize int64
	UserAgent   string
	Headers     map[string]string
	GlobalRate  float64
	PerHostRate float64
	DryRun      bool
	Concurrency int
}

const (
	defaultProbeTimeout     = 10 * time.Second
	defaultProbeMaxBody     = 100 * 1024 // 100KB is enough for a title and headers
	defaultProbeConcurrency = 10
	defaultProbeUserAgent   = "scoutr/1.0 (security research)"
)

func (o Options) normalized() Options {
	if o.Timeout <= 0 {
		o.Timeout = defaultProbeTimeout
	}
	if o.MaxBodySize <= 0 {
		o.MaxBodySize = defaultProbeMaxBody
	}
	if o.UserAgent == "" {
		o.UserAgent = defaultProbeUserAgent
	}
	if o.Concurrency < 1 {
		o.Concurrency = defaultProbeConcurrency
	}
	return o
}

// titleRegex extracts the HTML title from a response body.
var titleRegex = regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)

// Hosts probes multiple hosts concurrently and returns one result per host, in
// input order. A host that answers on neither scheme is reported as not live
// rather than as an error.
func Hosts(ctx context.Context, s *scope.Scope, hosts []string, opts Options) ([]*Result, error) {
	opts = opts.normalized()
	client := httpx.New(httpx.Config{
		Scope:         s,
		Timeout:       opts.Timeout,
		MaxBodySize:   opts.MaxBodySize,
		GlobalRate:    opts.GlobalRate,
		PerHostRate:   opts.PerHostRate,
		DryRun:        opts.DryRun,
		UserAgent:     opts.UserAgent,
		CustomHeaders: opts.Headers,
	})

	results := make([]*Result, len(hosts))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res, err := probeHost(ctx, client, h)
			if err != nil {
				res = &Result{Host: h, Error: err.Error()}
			}
			results[i] = res
		}(i, host)
	}
	wg.Wait()

	return results, nil
}

// probeHost tries HTTPS first and falls back to HTTP. HTTP-level failures are
// results ("not live"), not probe errors.
func probeHost(ctx context.Context, client *httpx.Client, host string) (*Result, error) {
	if res, err := probeURL(ctx, client, host, "https"); err == nil {
		return res, nil
	}

	res, err := probeURL(ctx, client, host, "http")
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	return res, nil
}

// probeURL requests one scheme for a host and extracts the probe metadata.
func probeURL(ctx context.Context, client *httpx.Client, host, scheme string) (*Result, error) {
	u := scheme + "://" + host
	resp, err := client.Get(ctx, u)
	if err != nil {
		return &Result{Host: host}, err
	}
	defer resp.Body.Close()

	res := &Result{
		Host:       host,
		URL:        u,
		Live:       true,
		HTTPS:      scheme == "https",
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		ContentLen: resp.ContentLength,
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		res.Redirect = resp.Header.Get("Location")
	}
	body, _ := io.ReadAll(resp.Body)
	if matches := titleRegex.FindSubmatch(body); len(matches) > 1 {
		res.Title = strings.TrimSpace(string(matches[1]))
	}
	return res, nil
}
