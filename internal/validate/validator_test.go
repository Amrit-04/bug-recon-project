package validate

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
)

func createTestScope(t *testing.T) *scope.Scope {
	content := `
in_scope:
  - "example.com"
  - "*.example.com"
out_of_scope:
  - "admin.example.com"
`
	tmp, err := os.CreateTemp("", "scope-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmp.Close()

	s, err := scope.LoadFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("failed to load scope: %v", err)
	}
	return s
}

func TestGate1ScopeVerification(t *testing.T) {
	s := createTestScope(t)
	validator := NewValidator(s)

	// In-scope finding
	f1 := findings.NewFinding("HDR-1", "headers", "api.example.com", "Missing HSTS", findings.SeverityMedium, findings.ConfidenceHigh)
	f1.Evidence = "HTTP/1.1 200 OK\nServer: nginx"
	vf1 := validator.ValidateFinding(context.Background(), f1)
	if !vf1.GateResults[0].Passed {
		t.Errorf("expected Gate 1 to pass for in-scope target")
	}

	// Out-of-scope finding
	f2 := findings.NewFinding("HDR-1", "headers", "admin.example.com", "Missing HSTS", findings.SeverityMedium, findings.ConfidenceHigh)
	f2.Evidence = "HTTP/1.1 200 OK"
	vf2 := validator.ValidateFinding(context.Background(), f2)
	if vf2.GateResults[0].Passed {
		t.Errorf("expected Gate 1 to fail for out-of-scope target")
	}
	if vf2.Status != StatusSuppressed {
		t.Errorf("expected status Suppressed for out-of-scope target, got %s", vf2.Status)
	}
}

func TestGate2And3Soft404AndSignatures(t *testing.T) {
	s := createTestScope(t)
	validator := NewValidator(s)

	// Fake .git/HEAD returning SPA HTML fallback
	fFakeGit := findings.NewFinding("EXP-GIT", "exposure", "api.example.com", "Exposed .git/HEAD", findings.SeverityHigh, findings.ConfidenceHigh)
	fFakeGit.Path = "/.git/HEAD"
	fFakeGit.Evidence = "<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>"

	vfFakeGit := validator.ValidateFinding(context.Background(), fFakeGit)
	if vfFakeGit.Status != StatusSuppressed {
		t.Errorf("expected HTML SPA .git/HEAD to be Suppressed, got %s", vfFakeGit.Status)
	}
	if !strings.Contains(vfFakeGit.SuppressionWhy, "Soft-404") && !strings.Contains(vfFakeGit.SuppressionWhy, "signature") {
		t.Errorf("expected suppression reason to reference Soft-404 or signature, got: %s", vfFakeGit.SuppressionWhy)
	}

	// Real .git/HEAD returning valid ref
	fRealGit := findings.NewFinding("EXP-GIT", "exposure", "api.example.com", "Exposed .git/HEAD", findings.SeverityHigh, findings.ConfidenceHigh)
	fRealGit.Path = "/.git/HEAD"
	fRealGit.Evidence = "ref: refs/heads/main\n"

	vfRealGit := validator.ValidateFinding(context.Background(), fRealGit)
	if !vfRealGit.GateResults[1].Passed || !vfRealGit.GateResults[2].Passed {
		t.Errorf("expected real .git/HEAD to pass Gates 2 and 3: %+v", vfRealGit.GateResults)
	}

	// Real .env
	fRealEnv := findings.NewFinding("EXP-ENV", "exposure", "api.example.com", "Exposed .env", findings.SeverityHigh, findings.ConfidenceHigh)
	fRealEnv.Path = "/.env"
	fRealEnv.Evidence = "DB_USER=root\nDB_PASS=secret123\nAPP_KEY=base64:xyz"

	vfRealEnv := validator.ValidateFinding(context.Background(), fRealEnv)
	if !vfRealEnv.GateResults[1].Passed || !vfRealEnv.GateResults[2].Passed {
		t.Errorf("expected real .env to pass Gates 2 and 3")
	}

	// Fake .env returning 404 HTML page
	fFakeEnv := findings.NewFinding("EXP-ENV", "exposure", "api.example.com", "Exposed .env", findings.SeverityHigh, findings.ConfidenceHigh)
	fFakeEnv.Path = "/.env"
	fFakeEnv.Evidence = "<html><body><h1>404 Not Found</h1></body></html>"

	vfFakeEnv := validator.ValidateFinding(context.Background(), fFakeEnv)
	if vfFakeEnv.Status != StatusSuppressed {
		t.Errorf("expected HTML .env to be suppressed, got %s", vfFakeEnv.Status)
	}
}

func TestGate4ImpactClassification(t *testing.T) {
	s := createTestScope(t)
	validator := NewValidator(s)

	// Missing header on static image
	fStatic := findings.NewFinding("HDR-HSTS", "headers", "api.example.com", "Missing HSTS Header", findings.SeverityMedium, findings.ConfidenceHigh)
	fStatic.Path = "/logo.png"
	fStatic.Evidence = "HTTP/1.1 200 OK\nContent-Type: image/png"

	vfStatic := validator.ValidateFinding(context.Background(), fStatic)
	if vfStatic.Status != StatusNeedsManualReview {
		t.Errorf("expected static asset header absence to be NeedsManualReview, got %s", vfStatic.Status)
	}

	// Missing header on main app path
	fApp := findings.NewFinding("HDR-HSTS", "headers", "api.example.com", "Missing HSTS Header", findings.SeverityMedium, findings.ConfidenceHigh)
	fApp.Path = "/login"
	fApp.Evidence = "HTTP/1.1 200 OK\nContent-Type: text/html"

	vfApp := validator.ValidateFinding(context.Background(), fApp)
	if vfApp.Status != StatusVerified {
		t.Errorf("expected app path header absence to be Verified, got %s", vfApp.Status)
	}
}

func TestGate5EvidenceRedaction(t *testing.T) {
	evidence := "Found credentials: AKIAIOSFODNN7EXAMPLE and Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeak"
	redacted := RedactEvidence(evidence)

	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("JWT token was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "AKIA[REDACTED_AWS_KEY]") {
		t.Errorf("Expected REDACTED_AWS_KEY placeholder")
	}
}

func TestGate6DeduplicationAndGrouping(t *testing.T) {
	s := createTestScope(t)
	validator := NewValidator(s)

	f1 := findings.NewFinding("HDR-CSP", "headers", "api.example.com", "Missing CSP", findings.SeverityMedium, findings.ConfidenceHigh)
	f1.RuleID = "CSP-01"
	f1.Path = "/app"
	f1.Evidence = "HTTP/1.1 200 OK"

	f2 := findings.NewFinding("HDR-CSP", "headers", "api.example.com", "Missing CSP", findings.SeverityMedium, findings.ConfidenceHigh)
	f2.RuleID = "CSP-01"
	f2.Path = "/dashboard"
	f2.Evidence = "HTTP/1.1 200 OK"

	f3 := findings.NewFinding("HDR-CSP", "headers", "api.example.com", "Missing CSP", findings.SeverityMedium, findings.ConfidenceHigh)
	f3.RuleID = "CSP-01"
	f3.Path = "/settings"
	f3.Evidence = "HTTP/1.1 200 OK"

	grouped := validator.ValidateAndGroup(context.Background(), []*findings.Finding{f1, f2, f3})
	if len(grouped) != 1 {
		t.Fatalf("expected 3 identical findings to group into 1, got %d", len(grouped))
	}

	vf := grouped[0]
	if len(vf.AffectedPaths) != 3 {
		t.Errorf("expected 3 affected paths in grouped finding, got %d: %v", len(vf.AffectedPaths), vf.AffectedPaths)
	}
}

func TestGate7RemediationMapping(t *testing.T) {
	s := createTestScope(t)
	validator := NewValidator(s)

	f := findings.NewFinding("HDR-HSTS", "headers", "api.example.com", "Missing Strict Transport Security", findings.SeverityMedium, findings.ConfidenceHigh)
	f.RuleID = "HSTS"
	f.Path = "/login"
	f.Evidence = "HTTP/1.1 200 OK"
	// No remediation explicitly set

	vf := validator.ValidateFinding(context.Background(), f)
	if vf.Finding.Remediation == "" {
		t.Errorf("expected automated remediation mapping for HSTS")
	}
	if len(vf.Finding.References) == 0 {
		t.Errorf("expected automated references mapping for HSTS")
	}
	if !strings.Contains(vf.Finding.Impact, "CWE-319") {
		t.Errorf("expected impact to mention CWE-319, got %s", vf.Finding.Impact)
	}
}
