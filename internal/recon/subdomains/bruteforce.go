package subdomains

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/scoutr/scoutr/internal/scope"
)

// BruteForce performs DNS brute force enumeration using a wordlist.
// For each in-scope domain, it tries each wordlist entry as a subdomain.
func BruteForce(ctx context.Context, s *scope.Scope, wordlistPath string) ([]string, error) {
	// Load wordlist
	wordlist, err := loadWordlist(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("load wordlist: %w", err)
	}

	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrency
	sem := make(chan struct{}, 50) // 50 concurrent DNS lookups

	// Process each base domain
	for _, domain := range s.InScope {
		// Skip wildcards
		if strings.HasPrefix(domain, "*.") {
			domain = domain[2:]
		}

		// Try each wordlist entry
		for _, prefix := range wordlist {
			subdomain := fmt.Sprintf("%s.%s", prefix, domain)

			// Check context
			select {
			case <-ctx.Done():
				return found, ctx.Err()
			default:
			}

			wg.Add(1)
			go func(target string) {
				defer wg.Done()

				// Acquire semaphore
				sem <- struct{}{}
				defer func() { <-sem }()

				// Try to resolve
				_, err := net.DefaultResolver.LookupHost(ctx, target)
				if err == nil {
					// DNS resolved - subdomain exists
					mu.Lock()
					found = append(found, target)
					mu.Unlock()
				}
			}(subdomain)
		}
	}

	wg.Wait()

	// Filter by scope
	var inScope []string
	for _, subdomain := range found {
		if s.IsInScope(subdomain) {
			inScope = append(inScope, subdomain)
		}
	}

	return inScope, nil
}

// loadWordlist loads the wordlist from the embedded default or a file.
func loadWordlist(path string) ([]string, error) {
	if path == "embedded" || path == "" {
		// Use embedded wordlist
		return strings.Split(DefaultWordlist, "\n"), nil
	}

	// Load from file
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}

	var words []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words, nil
}

// readFile is a placeholder for reading files (will use os.ReadFile in tests)
func readFile(path string) ([]byte, error) {
	// This will be replaced with os.ReadFile in actual implementation
	return nil, fmt.Errorf("not implemented")
}
