package checks

import (
	"context"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/httpx"
)

// MockCheck is a mock check for testing
type MockCheck struct {
	id   string
	desc string
}

func (m *MockCheck) ID() string {
	return m.id
}

func (m *MockCheck) Description() string {
	return m.desc
}

func (m *MockCheck) Run(ctx context.Context, target string, client *httpx.Client) ([]*findings.Finding, error) {
	return nil, nil
}

func TestRegister(t *testing.T) {
	// Clear registry
	globalRegistry.checks = make(map[string]Check)

	check := &MockCheck{id: "test1", desc: "Test check 1"}
	Register(check)

	retrieved := Get("test1")
	if retrieved == nil {
		t.Fatal("expected to retrieve registered check")
	}
	if retrieved.ID() != "test1" {
		t.Errorf("expected ID test1, got %s", retrieved.ID())
	}
}

func TestGetAll(t *testing.T) {
	// Clear registry
	globalRegistry.checks = make(map[string]Check)

	Register(&MockCheck{id: "check1", desc: "Check 1"})
	Register(&MockCheck{id: "check2", desc: "Check 2"})
	Register(&MockCheck{id: "check3", desc: "Check 3"})

	all := GetAll()
	if len(all) != 3 {
		t.Errorf("expected 3 checks, got %d", len(all))
	}
}

func TestFilter(t *testing.T) {
	// Clear registry
	globalRegistry.checks = make(map[string]Check)

	Register(&MockCheck{id: "headers", desc: "Headers check"})
	Register(&MockCheck{id: "cookies", desc: "Cookies check"})
	Register(&MockCheck{id: "cors", desc: "CORS check"})
	Register(&MockCheck{id: "tls", desc: "TLS check"})

	// Test include filter
	included := Filter([]string{"headers", "cookies"}, nil)
	if len(included) != 2 {
		t.Errorf("expected 2 checks, got %d", len(included))
	}

	// Test exclude filter
	excluded := Filter(nil, []string{"cors", "tls"})
	if len(excluded) != 2 {
		t.Errorf("expected 2 checks, got %d", len(excluded))
	}

	// Test no filter
	all := Filter(nil, nil)
	if len(all) != 4 {
		t.Errorf("expected 4 checks, got %d", len(all))
	}
}

func TestIDs(t *testing.T) {
	// Clear registry
	globalRegistry.checks = make(map[string]Check)

	Register(&MockCheck{id: "check1", desc: "Check 1"})
	Register(&MockCheck{id: "check2", desc: "Check 2"})

	ids := IDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs, got %d", len(ids))
	}

	// Check that both IDs are present (order doesn't matter)
	found := make(map[string]bool)
	for _, id := range ids {
		found[id] = true
	}
	if !found["check1"] || !found["check2"] {
		t.Error("expected both check1 and check2 in IDs")
	}
}
