// Package checks defines the Check interface and registry.
package checks

import (
	"context"
	"sync"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/httpx"
)

// Check is the interface that all security checks must implement.
type Check interface {
	// ID returns the unique identifier for this check (e.g., "headers", "cookies")
	ID() string

	// Description returns a human-readable description of what this check does
	Description() string

	// Run executes the check against a target and returns any findings
	Run(ctx context.Context, target string, client *httpx.Client) ([]*findings.Finding, error)
}

// Registry holds all registered checks.
type Registry struct {
	checks map[string]Check
	mu     sync.RWMutex
}

var globalRegistry = &Registry{
	checks: make(map[string]Check),
}

// Register adds a check to the global registry.
func Register(check Check) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.checks[check.ID()] = check
}

// GetAll returns all registered checks.
func GetAll() []Check {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	result := make([]Check, 0, len(globalRegistry.checks))
	for _, check := range globalRegistry.checks {
		result = append(result, check)
	}
	return result
}

// Get returns a check by ID, or nil if not found.
func Get(id string) Check {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	return globalRegistry.checks[id]
}

// Filter returns checks matching the given criteria.
// If include is non-empty, only checks in the list are returned.
// If exclude is non-empty, checks in the list are excluded.
func Filter(include, exclude []string) []Check {
	all := GetAll()

	// If include is specified, only return those
	if len(include) > 0 {
		includeMap := make(map[string]bool)
		for _, id := range include {
			includeMap[id] = true
		}

		var result []Check
		for _, check := range all {
			if includeMap[check.ID()] {
				result = append(result, check)
			}
		}
		return result
	}

	// Otherwise, return all except those in exclude
	if len(exclude) > 0 {
		excludeMap := make(map[string]bool)
		for _, id := range exclude {
			excludeMap[id] = true
		}

		var result []Check
		for _, check := range all {
			if !excludeMap[check.ID()] {
				result = append(result, check)
			}
		}
		return result
	}

	// No filter, return all
	return all
}

// IDs returns the IDs of all registered checks.
func IDs() []string {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	result := make([]string, 0, len(globalRegistry.checks))
	for id := range globalRegistry.checks {
		result = append(result, id)
	}
	return result
}
