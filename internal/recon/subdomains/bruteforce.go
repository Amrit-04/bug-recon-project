package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/scoutr/scoutr/internal/scope"
)

type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

var defaultResolver hostResolver = net.DefaultResolver

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

	// Deduplicate base domains
	seenDomains := make(map[string]bool)
	var baseDomains []string
	for _, domain := range s.InScope {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if strings.HasPrefix(domain, "*.") {
			domain = domain[2:]
		}
		if domain != "" && !seenDomains[domain] {
			seenDomains[domain] = true
			baseDomains = append(baseDomains, domain)
		}
	}

	// Process each base domain
	for _, domain := range baseDomains {
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
				_, err := defaultResolver.LookupHost(ctx, target)
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

	// Filter by scope and deduplicate
	seenFound := make(map[string]bool)
	var inScope []string
	for _, subdomain := range found {
		subdomain = strings.ToLower(strings.TrimSpace(subdomain))
		if subdomain != "" && !seenFound[subdomain] && s.IsInScope(subdomain) {
			seenFound[subdomain] = true
			inScope = append(inScope, subdomain)
		}
	}

	return inScope, nil
}

// loadWordlist loads the wordlist from the embedded default or a file.
func loadWordlist(path string) ([]string, error) {
	var rawData []byte
	if path == "embedded" || path == "" {
		rawData = []byte(DefaultWordlist)
	} else {
		data, err := readFile(path)
		if err != nil {
			return nil, err
		}
		rawData = data
	}

	var words []string
	scanner := bufio.NewScanner(bytes.NewReader(rawData))
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words, nil
}

// readFile reads a file from disk.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
