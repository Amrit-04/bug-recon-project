package report

import (
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

func TestReportGeneration(t *testing.T) {
	f := findings.NewFinding("EXP-01", "exposure", "api.example.com", "Exposed .env configuration", findings.SeverityHigh, findings.ConfidenceHigh)
	f.RuleID = "ENV-01"
	f.Path = "/.env"
	f.Evidence = "DB_HOST=127.0.0.1"
	f.Remediation = "Remove .env from public web root"
	f.References = []string{"https://example.com/cwe-200"}

	vf := &validate.ValidatedFinding{
		Finding:       f,
		Status:        validate.StatusVerified,
		AffectedPaths: []string{"/.env"},
	}

	// 1. Markdown
	md := GenerateMarkdown("api.example.com", []*validate.ValidatedFinding{vf})
	if !strings.Contains(md, "scoutr Security Posture Report") {
		t.Errorf("expected header in markdown report")
	}
	if !strings.Contains(md, "Exposed .env configuration") {
		t.Errorf("expected finding title in markdown report")
	}
	if !strings.Contains(md, "DB_HOST=127.0.0.1") {
		t.Errorf("expected evidence in markdown report")
	}

	// 2. HTML
	html := GenerateHTML("api.example.com", []*validate.ValidatedFinding{vf})
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("expected valid HTML structure")
	}
	if !strings.Contains(html, "badge-high") {
		t.Errorf("expected high severity badge in HTML")
	}
	if !strings.Contains(html, "Exposed .env configuration") {
		t.Errorf("expected finding title in HTML")
	}
	if !strings.Contains(html, "toggleTheme()") {
		t.Errorf("expected dark/light mode toggle in HTML")
	}
}
