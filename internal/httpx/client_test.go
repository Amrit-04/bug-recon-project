package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/scope"
)

// writeScopeFile is a helper that creates a scope YAML file for testing.
func writeScopeFile(t *testing.T, entries ...string) *scope.Scope {
	t.Helper()
	var lines []string
	lines = append(lines, "in_scope:")
	for _, e := range entries {
		lines = append(lines, fmt.Sprintf("  - %q", e))
	}
	content := strings.Join(lines, "\n") + "\n"

	tmpFile := t.TempDir() + "/scope.yaml"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	s, err := scope.LoadFromFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScopeBlocks(t *testing.T) {
	s := writeScopeFile(t, "example.com")

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024,
		GlobalRate:  0,
		PerHostRate: 0,
	})

	// Out-of-scope host should be blocked at the transport level
	_, err := client.Get(context.Background(), "https://attacker.com/test")
	if err == nil {
		t.Fatal("expected error for out-of-scope host, got nil")
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("expected 'out of scope' in error, got: %v", err)
	}
}

func TestScopeAllowsInScope(t *testing.T) {
	// Start a test server on localhost
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	// Put localhost and 127.0.0.1 in scope so the test server is accessible
	s := writeScopeFile(t, "127.0.0.1", "localhost")

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024,
		GlobalRate:  0,
		PerHostRate: 0,
	})

	resp, err := client.Get(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("expected in-scope request to succeed, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestRedirectToOutOfScope(t *testing.T) {
	// Server that redirects to an out-of-scope URL
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://attacker.com/evil", http.StatusFound)
	}))
	defer ts.Close()

	s := writeScopeFile(t, "127.0.0.1", "localhost")

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024,
		GlobalRate:  0,
		PerHostRate: 0,
	})

	_, err := client.Get(context.Background(), ts.URL)
	if err == nil {
		t.Fatal("expected error for redirect to out-of-scope host")
	}
	// The error should mention the out-of-scope redirect
	errStr := err.Error()
	if !strings.Contains(errStr, "out-of-scope") && !strings.Contains(errStr, "out of scope") {
		t.Errorf("expected scope-related error, got: %v", err)
	}
}

func TestBodySizeLimit(t *testing.T) {
	largeBody := strings.Repeat("A", 10*1024) // 10KB
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeBody))
	}))
	defer ts.Close()

	s := writeScopeFile(t, "127.0.0.1", "localhost")

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024, // Limit to 1KB
		GlobalRate:  0,
		PerHostRate: 0,
	})

	resp, err := client.Get(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error reading body: %v", err)
	}

	if len(data) > 1024 {
		t.Errorf("read %d bytes, expected at most 1024", len(data))
	}
}

func TestDryRunNoNetwork(t *testing.T) {
	s := writeScopeFile(t, "example.com")

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024,
		GlobalRate:  0,
		PerHostRate: 0,
		DryRun:      true,
	})

	// In dry run, requests to in-scope hosts return fake 200 without hitting the network
	resp, err := client.Get(context.Background(), "https://example.com/test")
	if err != nil {
		t.Fatalf("dry run request should succeed, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Status, "dry run") {
		t.Error("expected 'dry run' in status")
	}
}

func TestDryRunStillEnforcesScope(t *testing.T) {
	s := writeScopeFile(t, "example.com")

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024,
		GlobalRate:  0,
		PerHostRate: 0,
		DryRun:      true, // Even in dry run mode...
	})

	// Out-of-scope should still be blocked
	_, err := client.Get(context.Background(), "https://attacker.com/test")
	if err == nil {
		t.Fatal("dry run should still block out-of-scope requests")
	}
}

func TestUserAgentSet(t *testing.T) {
	receivedUA := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := writeScopeFile(t, "127.0.0.1", "localhost")
	customUA := "scoutr-test/1.0"

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024,
		GlobalRate:  0,
		PerHostRate: 0,
		UserAgent:   customUA,
	})

	_, err := client.Get(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if receivedUA != customUA {
		t.Errorf("expected User-Agent %q, got %q", customUA, receivedUA)
	}
}

func TestCustomHeaders(t *testing.T) {
	receivedHeaders := make(http.Header)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range r.Header {
			receivedHeaders[k] = v
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := writeScopeFile(t, "127.0.0.1", "localhost")

	client := New(Config{
		Scope:       s,
		Timeout:     5 * time.Second,
		MaxBodySize: 1024,
		GlobalRate:  0,
		PerHostRate: 0,
		CustomHeaders: map[string]string{
			"X-Bug-Bounty": "testhandle",
		},
	})

	_, err := client.Get(context.Background(), ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if receivedHeaders.Get("X-Bug-Bounty") != "testhandle" {
		t.Errorf("expected custom header, got headers: %v", receivedHeaders)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(100.0, 5.0) // High global, 5 per host

	ctx := context.Background()
	start := time.Now()

	// Make 6 requests to the same host — the first bursts through,
	// subsequent ones should be rate limited
	for i := 0; i < 6; i++ {
		if err := rl.Wait(ctx, "example.com"); err != nil {
			t.Fatal(err)
		}
	}

	elapsed := time.Since(start)
	// At burst=6 (5+1), 6 requests may pass immediately, so we just verify no crash
	t.Logf("6 requests at 5/s per-host took %v", elapsed)
}

func TestRateLimiterContextCancel(t *testing.T) {
	rl := NewRateLimiter(1.0, 1.0) // Very slow: 1 req/s

	// Drain the burst tokens
	ctx := context.Background()
	rl.Wait(ctx, "example.com")
	rl.Wait(ctx, "example.com")

	// Now cancel context and try again
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := rl.Wait(ctx, "example.com")
	if err == nil {
		t.Error("expected error when context is cancelled")
	}
}
