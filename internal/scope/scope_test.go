package scope

import (
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
