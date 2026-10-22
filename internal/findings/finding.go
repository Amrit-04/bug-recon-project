// Package findings defines the Finding struct and related types.
package findings

import (
	"fmt"
	"time"
)

// Severity represents the severity of a finding.
type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Confidence represents the confidence level of a finding.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Finding represents a security finding from a check.
type Finding struct {
	// Identification
	ID        string `json:"id"`
	CheckName string `json:"check_name"`

	// Target
	Target string `json:"target"` // Host or URL
	Path   string `json:"path,omitempty"`

	// Finding details
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`

	// Evidence
	Evidence string `json:"evidence,omitempty"` // Trimmed request/response snippet
	Request  string `json:"request,omitempty"`  // HTTP request (for curl reproduction)
	Response string `json:"response,omitempty"` // HTTP response snippet

	// Impact and remediation
	Impact      string   `json:"impact,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`

	// Metadata
	Timestamp time.Time `json:"timestamp"`
}

// Key returns a deterministic key for deduplication.
func (f *Finding) Key() string {
	return fmt.Sprintf("%s:%s:%s:%s", f.CheckName, f.Target, f.Path, f.Severity)
}

// Validate checks that the finding has required fields.
func (f *Finding) Validate() error {
	if f.ID == "" {
		return fmt.Errorf("finding ID is required")
	}
	if f.CheckName == "" {
		return fmt.Errorf("check name is required")
	}
	if f.Target == "" {
		return fmt.Errorf("target is required")
	}
	if f.Title == "" {
		return fmt.Errorf("title is required")
	}
	return nil
}

// NewFinding creates a new finding with a timestamp.
func NewFinding(id, checkName, target, title string, severity Severity, confidence Confidence) *Finding {
	return &Finding{
		ID:         id,
		CheckName:  checkName,
		Target:     target,
		Title:      title,
		Severity:   severity,
		Confidence: confidence,
		Timestamp:  time.Now(),
	}
}
