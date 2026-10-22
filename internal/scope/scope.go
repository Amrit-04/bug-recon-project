package scope

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope defines which targets are allowed and which are explicitly forbidden.
type Scope struct {
	InScope     []string `yaml:"in_scope"`
	OutOfScope  []string `yaml:"out_of_scope"`
	inPatterns  []pattern
	outPatterns []pattern
}

// pattern represents a compiled scope pattern (literal or wildcard).
type pattern struct {
	original string
	wildcard bool
	prefix   string // For *.example.com, this is ".example.com"
	literal  string // For exact matches
}

// LoadFromFile reads and parses a scope YAML file.
func LoadFromFile(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scope file: %w", err)
	}

	var s Scope
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse scope YAML: %w", err)
	}

	if len(s.InScope) == 0 {
		return nil, fmt.Errorf("scope file must define at least one in_scope entry")
	}

	// Compile patterns
	s.inPatterns = compilePatterns(s.InScope)
	s.outPatterns = compilePatterns(s.OutOfScope)

	return &s, nil
}

// compilePatterns converts a list of scope strings into compiled patterns.
func compilePatterns(entries []string) []pattern {
	var patterns []pattern
	for _, entry := range entries {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}

		if strings.HasPrefix(entry, "*.") {
			// Wildcard pattern: *.example.com matches foo.example.com, a.b.example.com
			// but NOT example.com itself (the bare domain must be listed separately)
			patterns = append(patterns, pattern{
				original: entry,
				wildcard: true,
				prefix:   entry[1:], // Strip the * to get ".example.com"
			})
		} else {
			// Literal pattern: exact match only
			patterns = append(patterns, pattern{
				original: entry,
				wildcard: false,
				literal:  entry,
			})
		}
	}
	return patterns
}

// IsInScope checks if the given host is in scope.
// Out-of-scope always wins over in-scope.
func (s *Scope) IsInScope(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))

	// Strip port if present
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Check if it's actually a port (IPv6 addresses have colons too)
		if !strings.Contains(host[idx:], "]") {
			host = host[:idx]
		}
	}

	// Out-of-scope always wins
	if s.matches(host, s.outPatterns) {
		return false
	}

	// Check in-scope
	return s.matches(host, s.inPatterns)
}

// IsURLInScope checks if a full URL is in scope (by extracting the host).
func (s *Scope) IsURLInScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return s.IsInScope(u.Host)
}

// matches returns true if the host matches any of the patterns.
func (s *Scope) matches(host string, patterns []pattern) bool {
	for _, p := range patterns {
		if p.wildcard {
			// For *.example.com (prefix = ".example.com"):
			// - foo.example.com matches (ends with .example.com)
			// - a.b.example.com matches
			// - example.com does NOT match (must be listed as bare domain)
			if strings.HasSuffix(host, p.prefix) {
				return true
			}
		} else {
			// Exact match
			if host == p.literal {
				return true
			}
		}
	}
	return false
}

// String returns a human-readable summary of the scope.
func (s *Scope) String() string {
	return fmt.Sprintf("In-scope: %v | Out-of-scope: %v", s.InScope, s.OutOfScope)
}
