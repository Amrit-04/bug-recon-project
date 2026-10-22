// Package probe provides live host probing.
package probe

import (
	"context"

	"github.com/scoutr/scoutr/internal/scope"
)

// Result represents the result of probing a single host.
type Result struct {
	Host       string `json:"host"`
	URL        string `json:"url"`
	Live       bool   `json:"live"`
	StatusCode int    `json:"status_code,omitempty"`
	Title      string `json:"title,omitempty"`
	Server     string `json:"server,omitempty"`
}

// Host probes a single host to determine if it's live.
func Host(ctx context.Context, s *scope.Scope, host string) (*Result, error) {
	// TODO: Phase 3 - implement host probing
	return &Result{
		Host: host,
		Live: false,
	}, nil
}
