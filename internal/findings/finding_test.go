package findings

import (
	"testing"
	"time"
)

func TestFindingKey(t *testing.T) {
	f1 := NewFinding("HDR-001", "headers", "example.com", "Missing HSTS", SeverityMedium, ConfidenceHigh)
	f1.Path = "/test"

	f2 := NewFinding("HDR-001", "headers", "example.com", "Missing HSTS", SeverityMedium, ConfidenceHigh)
	f2.Path = "/test"

	if f1.Key() != f2.Key() {
		t.Errorf("identical findings should have the same key: %s vs %s", f1.Key(), f2.Key())
	}

	// Different path
	f3 := NewFinding("HDR-001", "headers", "example.com", "Missing HSTS", SeverityMedium, ConfidenceHigh)
	f3.Path = "/other"

	if f1.Key() == f3.Key() {
		t.Error("findings with different paths should have different keys")
	}

	// Different severity
	f4 := NewFinding("HDR-001", "headers", "example.com", "Missing HSTS", SeverityHigh, ConfidenceHigh)
	f4.Path = "/test"

	if f1.Key() == f4.Key() {
		t.Error("findings with different severities should have different keys")
	}

	// Different RuleID
	f5 := NewFinding("HDR-001", "headers", "example.com", "Missing HSTS", SeverityMedium, ConfidenceHigh)
	f5.Path = "/test"
	f5.RuleID = "HSTS-01"

	f6 := NewFinding("HDR-001", "headers", "example.com", "Missing CSP", SeverityMedium, ConfidenceHigh)
	f6.Path = "/test"
	f6.RuleID = "CSP-01"

	if f5.Key() == f6.Key() {
		t.Error("findings with different rule IDs should have different keys")
	}
}

func TestFindingValidate(t *testing.T) {
	tests := []struct {
		name      string
		finding   *Finding
		wantError bool
	}{
		{
			name:      "valid finding",
			finding:   NewFinding("HDR-001", "headers", "example.com", "Missing HSTS", SeverityMedium, ConfidenceHigh),
			wantError: false,
		},
		{
			name: "missing ID",
			finding: &Finding{
				CheckName: "headers",
				Target:    "example.com",
				Title:     "Missing HSTS",
			},
			wantError: true,
		},
		{
			name: "missing check name",
			finding: &Finding{
				ID:     "HDR-001",
				Target: "example.com",
				Title:  "Missing HSTS",
			},
			wantError: true,
		},
		{
			name: "missing target",
			finding: &Finding{
				ID:        "HDR-001",
				CheckName: "headers",
				Title:     "Missing HSTS",
			},
			wantError: true,
		},
		{
			name: "missing title",
			finding: &Finding{
				ID:        "HDR-001",
				CheckName: "headers",
				Target:    "example.com",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.finding.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestNewFinding(t *testing.T) {
	before := time.Now()
	f := NewFinding("HDR-001", "headers", "example.com", "Missing HSTS", SeverityMedium, ConfidenceHigh)
	after := time.Now()

	if f.ID != "HDR-001" {
		t.Errorf("expected ID HDR-001, got %s", f.ID)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected severity medium, got %s", f.Severity)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("expected confidence high, got %s", f.Confidence)
	}
	if f.Timestamp.Before(before) || f.Timestamp.After(after) {
		t.Errorf("timestamp not in expected range")
	}
}

func TestSeverityConstants(t *testing.T) {
	severities := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh}
	if len(severities) != 4 {
		t.Error("expected 4 severity levels")
	}
}

func TestConfidenceConstants(t *testing.T) {
	confidences := []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}
	if len(confidences) != 3 {
		t.Error("expected 3 confidence levels")
	}
}
