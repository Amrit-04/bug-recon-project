package scope

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantError bool
	}{
		{
			name: "valid scope",
			content: `in_scope:
  - example.com
  - "*.example.com"
out_of_scope:
  - admin.example.com
`,
			wantError: false,
		},
		{
			name: "empty in_scope",
			content: `in_scope: []
out_of_scope: []
`,
			wantError: true,
		},
		{
			name:      "invalid YAML",
			content:   `in_scope: [unclosed`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), "scope.yaml")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			s, err := LoadFromFile(tmpFile)
			if (err != nil) != tt.wantError {
				t.Errorf("LoadFromFile() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if !tt.wantError && s == nil {
				t.Error("expected non-nil scope")
			}
		})
	}
}

func TestIsInScope(t *testing.T) {
	s := &Scope{
		InScope:    []string{"example.com", "*.test.com", "api.prod.net"},
		OutOfScope: []string{"admin.test.com", "*.internal.example.com"},
	}
	s.inPatterns = compilePatterns(s.InScope)
	s.outPatterns = compilePatterns(s.OutOfScope)

	tests := []struct {
		host    string
		inScope bool
	}{
		// Exact matches
		{"example.com", true},
		{"api.prod.net", true},

		// Wildcard matches (*.test.com)
		{"foo.test.com", true},
		{"a.b.test.com", true},
		{"test.com", false}, // Bare domain NOT matched by *.test.com

		// Out-of-scope wins
		{"admin.test.com", false}, // In wildcard but out-of-scope
		{"x.internal.example.com", false},

		// Not in scope
		{"google.com", false},
		{"attacker.com", false},

		// Port stripping
		{"example.com:443", true},
		{"foo.test.com:8080", true},

		// Case insensitivity
		{"Example.COM", true},
		{"FOO.TEST.COM", true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := s.IsInScope(tt.host)
			if got != tt.inScope {
				t.Errorf("IsInScope(%q) = %v, want %v", tt.host, got, tt.inScope)
			}
		})
	}
}

func TestIsURLInScope(t *testing.T) {
	s := &Scope{
		InScope:    []string{"example.com"},
		OutOfScope: []string{},
	}
	s.inPatterns = compilePatterns(s.InScope)
	s.outPatterns = compilePatterns(s.OutOfScope)

	tests := []struct {
		url     string
		inScope bool
	}{
		{"https://example.com/path", true},
		{"http://example.com:8080/test", true},
		{"https://other.com/path", false},
		{"not-a-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := s.IsURLInScope(tt.url)
			if got != tt.inScope {
				t.Errorf("IsURLInScope(%q) = %v, want %v", tt.url, got, tt.inScope)
			}
		})
	}
}

func TestWildcardPrecedence(t *testing.T) {
	// Out-of-scope must always win, even if in-scope wildcards would match
	s := &Scope{
		InScope:    []string{"*.example.com", "example.com"},
		OutOfScope: []string{"restricted.example.com"},
	}
	s.inPatterns = compilePatterns(s.InScope)
	s.outPatterns = compilePatterns(s.OutOfScope)

	if s.IsInScope("restricted.example.com") {
		t.Error("out-of-scope entry should block wildcard match")
	}
	if !s.IsInScope("allowed.example.com") {
		t.Error("other wildcards should still match")
	}
}

type mockDNSResolver struct {
	records map[string][]string // host -> IP strings
}

func (m *mockDNSResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if ips, ok := m.records[host]; ok {
		var out []net.IP
		for _, ipStr := range ips {
			out = append(out, net.ParseIP(ipStr))
		}
		return out, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

func TestIPAndCIDRScope(t *testing.T) {
	s := New(
		[]string{"*.example.com", "192.168.1.0/24", "93.184.216.34"},
		[]string{"192.168.1.100", "10.0.0.0/8", "127.0.0.1"},
	)

	// In-scope IP tests
	if !s.IsInScope("192.168.1.50") {
		t.Errorf("expected 192.168.1.50 to be in scope")
	}
	if !s.IsInScope("93.184.216.34") {
		t.Errorf("expected 93.184.216.34 to be in scope")
	}

	// Out-of-scope IP tests
	if s.IsInScope("192.168.1.100") {
		t.Errorf("expected excluded 192.168.1.100 to be out of scope")
	}
	if s.IsInScope("10.5.5.5") {
		t.Errorf("expected 10.5.5.5 (10.0.0.0/8) to be out of scope")
	}
	if s.IsInScope("127.0.0.1") {
		t.Errorf("expected 127.0.0.1 to be out of scope")
	}
}

func TestValidateHostAndDNS(t *testing.T) {
	s := New(
		[]string{"*.example.com", "example.com"},
		[]string{"10.0.0.0/8", "192.168.0.0/16", "127.0.0.1"},
	)
	mock := &mockDNSResolver{
		records: map[string][]string{
			"safe.example.com":     {"93.184.216.34"},
			"internal.example.com": {"10.0.0.5"},
			"loopback.example.com": {"127.0.0.1"},
			"multi.example.com":    {"93.184.216.34", "192.168.1.5"},
		},
	}
	s.SetResolver(mock)
	ctx := context.Background()

	// Safe host: in scope and resolves to public IP
	ips, err := s.ValidateHostAndDNS(ctx, "safe.example.com")
	if err != nil || len(ips) == 0 {
		t.Fatalf("expected safe host to pass DNS validation, got: %v", err)
	}

	// Hostname matches in_scope, but resolves to out_of_scope 10.0.0.5
	_, err = s.ValidateHostAndDNS(ctx, "internal.example.com")
	if err == nil {
		t.Errorf("expected error when host resolves to out-of-scope IP 10.0.0.5")
	}

	// Hostname resolves to 127.0.0.1
	_, err = s.ValidateHostAndDNS(ctx, "loopback.example.com")
	if err == nil {
		t.Errorf("expected error when host resolves to out-of-scope IP 127.0.0.1")
	}

	// Multi-A record where one IP is out-of-scope
	_, err = s.ValidateHostAndDNS(ctx, "multi.example.com")
	if err == nil {
		t.Errorf("expected error when at least one resolved IP is out-of-scope")
	}

	// Unresolvable host
	_, err = s.ValidateHostAndDNS(ctx, "unknown.example.com")
	if err == nil {
		t.Errorf("expected error for unresolvable host")
	}
}
