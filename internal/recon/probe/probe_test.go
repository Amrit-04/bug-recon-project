package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/scoutr/scoutr/internal/scope"
)

func testScope(t *testing.T, inScope ...string) *scope.Scope {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	content := "in_scope:\n"
	for _, host := range inScope {
		content += "  - " + host + "\n"
	}
	content += "out_of_scope: []\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := scope.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHostsProbesLiveHostWithConfiguredHeaders(t *testing.T) {
	var mu sync.Mutex
	var gotUA, gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotUA = r.UserAgent()
		gotHeader = r.Header.Get("X-Scoutr-Test")
		mu.Unlock()
		w.Header().Set("Server", "test-server")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><title>  Hello  </title></html>"))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	s := testScope(t, "127.0.0.1")

	results, err := Hosts(context.Background(), s, []string{host}, Options{
		UserAgent: "scoutr-test-agent",
		Headers:   map[string]string{"X-Scoutr-Test": "yes"},
	})
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if !res.Live || res.StatusCode != http.StatusOK {
		t.Fatalf("expected a live 200 response, got %+v", res)
	}
	if res.Title != "Hello" {
		t.Errorf("expected trimmed title %q, got %q", "Hello", res.Title)
	}
	if res.Server != "test-server" {
		t.Errorf("expected server header, got %q", res.Server)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotUA != "scoutr-test-agent" {
		t.Errorf("expected configured user agent, got %q", gotUA)
	}
	if gotHeader != "yes" {
		t.Errorf("expected custom header to be sent, got %q", gotHeader)
	}
}

func TestHostsPreservesInputOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<title>ok</title>"))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	hosts := []string{host, "out.example.com", host}

	results, err := Hosts(context.Background(), testScope(t, "127.0.0.1"), hosts, Options{Concurrency: 3})
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(results) != len(hosts) {
		t.Fatalf("expected %d results, got %d", len(hosts), len(results))
	}
	for i, want := range hosts {
		if results[i].Host != want {
			t.Errorf("result %d: expected host %q, got %q", i, want, results[i].Host)
		}
	}
}

func TestHostsRejectsOutOfScopeHostWithoutSending(t *testing.T) {
	s := testScope(t, "example.com")

	results, err := Hosts(context.Background(), s, []string{"not-in-scope.test"}, Options{})
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Live {
		t.Fatal("out-of-scope host must not be reported as live")
	}
	if !strings.Contains(results[0].Error, "scope") {
		t.Errorf("expected a scope error, got %q", results[0].Error)
	}
}
