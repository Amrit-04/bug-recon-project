package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/scope"
)

// crtShURL is the crt.sh API endpoint for certificate transparency logs.
const crtShURL = "https://crt.sh/?q=%%25.%s&output=json"

// CRTSHResult represents a single entry from crt.sh.
type CRTSHResult struct {
	IssuerName        string `json:"issuer_name"`
	Name              string `json:"name"`
	MinCertID         int    `json:"min_cert_id"`
	MinEntryTimestamp string `json:"min_entry_timestamp"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
}

// FromCRTSH enumerates subdomains from crt.sh certificate transparency logs.
// It queries for all certificates matching *.domain and extracts unique subdomains.
func FromCRTSH(ctx context.Context, s *scope.Scope) ([]string, error) {
	var allSubdomains []string

	// Query each in-scope domain
	for _, domain := range s.InScope {
		// Skip wildcards - we want the base domain to query
		if strings.HasPrefix(domain, "*.") {
			domain = domain[2:]
		}

		subdomains, err := queryCRTSH(ctx, domain)
		if err != nil {
			// Log warning but continue with other domains
			fmt.Printf("Warning: crt.sh query for %s failed: %v\n", domain, err)
			continue
		}

		// Filter by scope
		for _, subdomain := range subdomains {
			if s.IsInScope(subdomain) {
				allSubdomains = append(allSubdomains, subdomain)
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, s := range allSubdomains {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}

	return unique, nil
}

// queryCRTSH queries crt.sh for a single domain.
func queryCRTSH(ctx context.Context, domain string) ([]string, error) {
	// Build URL
	queryURL := fmt.Sprintf(crtShURL, domain)

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set User-Agent
	req.Header.Set("User-Agent", "scoutr/1.0 (security research)")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Parse JSON
	var results []CRTSHResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	// Extract unique subdomains
	subdomains := make(map[string]bool)
	for _, result := range results {
		// The 'name' field contains the certificate's SAN entries
		// It can contain multiple domains separated by newlines
		names := strings.Split(result.Name, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.ToLower(name)

			// Skip empty entries
			if name == "" {
				continue
			}

			// Handle wildcard certificates (*.example.com)
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}

			// Only include if it's a subdomain of our target
			if strings.HasSuffix(name, "."+domain) || name == domain {
				subdomains[name] = true
			}
		}
	}

	// Convert to slice
	var result []string
	for subdomain := range subdomains {
		result = append(result, subdomain)
	}

	return result, nil
}
