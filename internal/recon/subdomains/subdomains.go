// Package subdomains provides subdomain enumeration methods.
package subdomains

import (
	"context"
	_ "embed"

	"github.com/scoutr/scoutr/internal/scope"
)

//go:embed wordlist.txt
var DefaultWordlist string

const DefaultWordlistPath = "embedded"

// FromCRTSH enumerates subdomains from crt.sh certificate transparency logs.
func FromCRTSH(ctx context.Context, s *scope.Scope) ([]string, error) {
	// TODO: Phase 3 - implement passive enumeration via crt.sh JSON API
	return []string{}, nil
}

// BruteForce enumerates subdomains via DNS brute force using a wordlist.
func BruteForce(ctx context.Context, s *scope.Scope, wordlistPath string) ([]string, error) {
	// TODO: Phase 3 - implement active DNS brute force
	return []string{}, nil
}
