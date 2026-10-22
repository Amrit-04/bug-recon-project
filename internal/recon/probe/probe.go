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

// titleRegex extracts the HTML title from a response body.
var titleRegex = regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)

// Host probes a single host to determine if it's live and gather basic information.
func Host(ctx context.Context, s *scope.Scope, host string) (*Result, error) {
	result := &Result{
		Host: host,
	}

	// Create HTTP client with scope enforcement
	cfg := httpx.Config{
		Scope:       s,
		Timeout:     10 * time.Second,
		MaxBodySize: 1024 * 100, // 100KB for probing
		GlobalRate:  0,          // No rate limit for probing
		PerHostRate: 0,
		UserAgent:   "scoutr/1.0 (security research)",
	}
	client := httpx.New(cfg)

	// Try HTTPS first
	httpsURL := "https://" + host
	resp, err := client.Get(ctx, httpsURL)
	if err == nil {
		result.URL = httpsURL
		result.HTTPS = true
		result.Live = true
		result.StatusCode = resp.StatusCode
		result.Server = resp.Header.Get("Server")
		result.ContentLen = resp.ContentLength

		// Check for redirect
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			result.Redirect = resp.Header.Get("Location")
		}

		// Extract title
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if matches := titleRegex.FindSubmatch(body); len(matches) > 1 {
			result.Title = strings.TrimSpace(string(matches[1]))
		}

		return result, nil
	}

	// Try HTTP as fallback
	httpURL := "http://" + host
	resp, err = client.Get(ctx, httpURL)
	if err != nil {
		result.Error = err.Error()
		return result, nil // Not live, but not an error for probing
	}

	result.URL = httpURL
	result.HTTPS = false
	result.Live = true
	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")
	result.ContentLen = resp.ContentLength

	// Check for redirect
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.Redirect = resp.Header.Get("Location")
	}

	// Extract title
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if matches := titleRegex.FindSubmatch(body); len(matches) > 1 {
		result.Title = strings.TrimSpace(string(matches[1]))
	}

	return result, nil
}

// Hosts probes multiple hosts concurrently.
func Hosts(ctx context.Context, s *scope.Scope, hosts []string, concurrency int) ([]*Result, error) {
	results := make([]*Result, 0, len(hosts))
	resultChan := make(chan *Result, len(hosts))

	// Use a semaphore for concurrency limiting
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := Host(ctx, s, h)
			if err != nil {
				result = &Result{Host: h, Error: err.Error()}
			}
			resultChan <- result
		}(host)
	}

	// Wait for all probes and collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		results = append(results, result)
	}

	return results, nil
}
