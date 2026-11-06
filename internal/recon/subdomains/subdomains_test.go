package subdomains

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/scope"
)

func testScope(t *testing.T, inScope []string, outScope []string) *scope.Scope {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	content := "in_scope:\n"
	for _, host := range inScope {
		content += "  - \"" + host + "\"\n"
	}
	content += "out_of_scope:\n"
	for _, host := range outScope {
		content += "  - \"" + host + "\"\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := scope.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadWordlistEmbedded(t *testing.T) {
	for _, p := range []string{"embedded", ""} {
		words, err := loadWordlist(p)
		if err != nil {
			t.Fatalf("loadWordlist(%q): %v", p, err)
		}
		if len(words) == 0 {
			t.Fatalf("loadWordlist(%q) returned empty slice", p)
		}
		hasWWW := false
		for _, w := range words {
			if strings.ContainsAny(w, "\r\n \t") {
				t.Errorf("word %q contains whitespace or newline", w)
			}
			if strings.HasPrefix(w, "#") {
				t.Errorf("word %q is a comment", w)
			}
			if w == "www" {
				hasWWW = true
			}
		}
		if !hasWWW {
			t.Errorf("loadWordlist(%q) missing expected word 'www'", p)
		}
	}
}

func TestLoadWordlistCustomFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "custom.txt")
	content := "# comment line\n\nweb\r\napi\n# another comment\nadmin\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	words, err := loadWordlist(tmpFile)
	if err != nil {
		t.Fatalf("loadWordlist from file: %v", err)
	}
	want := []string{"web", "api", "admin"}
	if len(words) != len(want) {
		t.Fatalf("got %d words, want %d: %v", len(words), len(want), words)
	}
	for i, w := range want {
		if words[i] != w {
			t.Errorf("word[%d] = %q, want %q", i, words[i], w)
		}
	}

	// Missing file should return error
	if _, err := loadWordlist("nonexistent-file.txt"); err == nil {
		t.Fatal("expected error loading missing file")
	}
}

func TestFromCRTSH(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Simulate crt.sh response with multiple SAN names, wildcards, and out-of-scope targets
		resp := `[
			{"name": "sub1.example.com\nsub2.example.com"},
			{"name": "*.wild.example.com"},
			{"name": "admin.example.com\nexternal.other.com"}
		]`
		w.Write([]byte(resp))
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Override URL and HTTP client for deterministic testing
	oldURL := crtShURL
	oldClient := httpClient
	crtShURL = ts.URL + "/?q=%%25.%s&output=json"
	httpClient = ts.Client()
	defer func() {
		crtShURL = oldURL
		httpClient = oldClient
	}()

	s := testScope(t, []string{"example.com", "*.example.com"}, []string{"admin.example.com"})

	subs, err := FromCRTSH(context.Background(), s)
	if err != nil {
		t.Fatalf("FromCRTSH: %v", err)
	}

	foundMap := make(map[string]bool)
	for _, sub := range subs {
		foundMap[sub] = true
	}

	if !foundMap["sub1.example.com"] || !foundMap["sub2.example.com"] || !foundMap["wild.example.com"] {
		t.Errorf("missing expected subdomains in: %v", subs)
	}
	if foundMap["admin.example.com"] {
		t.Errorf("out-of-scope admin.example.com was not filtered: %v", subs)
	}
	if foundMap["external.other.com"] {
		t.Errorf("external.other.com was not filtered: %v", subs)
	}
}

func TestFromCRTSHServerError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	oldURL := crtShURL
	oldClient := httpClient
	crtShURL = ts.URL + "/?q=%%25.%s&output=json"
	httpClient = ts.Client()
	defer func() {
		crtShURL = oldURL
		httpClient = oldClient
	}()

	s := testScope(t, []string{"example.com"}, nil)
	subs, err := FromCRTSH(context.Background(), s)
	if err != nil {
		t.Fatalf("expected error to be handled gracefully, got: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected 0 subdomains on 500 error, got %d", len(subs))
	}
}

type mockResolver struct {
	validHosts map[string]bool
}

func (m *mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if m.validHosts[host] {
		return []string{"192.0.2.1"}, nil
	}
	return nil, fmt.Errorf("no such host")
}

func TestBruteForce(t *testing.T) {
	mock := &mockResolver{
		validHosts: map[string]bool{
			"api.example.com":       true,
			"forbidden.example.com": true,
		},
	}

	oldResolver := defaultResolver
	defaultResolver = mock
	defer func() {
		defaultResolver = oldResolver
	}()

	tmpFile := filepath.Join(t.TempDir(), "words.txt")
	content := "api\nforbidden\nnonexistent\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	s := testScope(t, []string{"example.com", "*.example.com"}, []string{"forbidden.example.com"})

	results, err := BruteForce(context.Background(), s, tmpFile)
	if err != nil {
		t.Fatalf("BruteForce: %v", err)
	}

	if len(results) != 1 || results[0] != "api.example.com" {
		t.Errorf("expected ['api.example.com'], got %v", results)
	}
}

func TestBruteForceContextCanceled(t *testing.T) {
	mock := &mockResolver{
		validHosts: map[string]bool{},
	}
	oldResolver := defaultResolver
	defaultResolver = mock
	defer func() {
		defaultResolver = oldResolver
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	s := testScope(t, []string{"example.com"}, nil)
	_, err := BruteForce(ctx, s, "embedded")
	if err == nil {
		t.Fatal("expected error with canceled context")
	}
}
