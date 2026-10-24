package validate

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
)

// ValidationStatus classifies the certainty and readiness of a finding.
type ValidationStatus string

const (
	// StatusVerified indicates the finding passed all 7 validation gates.
	StatusVerified ValidationStatus = "Verified"
	// StatusNeedsManualReview indicates potential finding requiring human verification (e.g., static asset).
	StatusNeedsManualReview ValidationStatus = "NeedsManualReview"
	// StatusSuppressed indicates confirmed false positive, out-of-scope, or soft-404 rejection.
	StatusSuppressed ValidationStatus = "Suppressed"
)

// GateResult details the outcome of one of the 7 validation gates.
type GateResult struct {
	GateID int    `json:"gate_id"`
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Reason string `json:"reason,omitempty"`
}

// ValidatedFinding encapsulates the original finding along with its validation verdict and gate history.
type ValidatedFinding struct {
	Finding        *findings.Finding `json:"finding"`
	Status         ValidationStatus  `json:"status"`
	GateResults    []GateResult      `json:"gate_results"`
	SuppressionWhy string            `json:"suppression_why,omitempty"`
	AffectedPaths  []string          `json:"affected_paths,omitempty"`
}

// BaselineChecker is an optional hook to compare an endpoint response against a baseline response.
type BaselineChecker func(ctx context.Context, target string) (isSoft404 bool, err error)

// Validator executes the 7-Check Readiness Gate.
type Validator struct {
	Scope           *scope.Scope
	BaselineChecker BaselineChecker
}

// NewValidator creates a new Validator configured with a Scope.
func NewValidator(s *scope.Scope) *Validator {
	return &Validator{
		Scope: s,
	}
}

// Secret redactor patterns
var (
	awsKeyRegex     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	jwtTokenRegex   = regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`)
	authHeaderRegex = regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)\s+)[^\r\n]+`)
)

// RedactEvidence masks sensitive tokens and credentials from evidence text.
func RedactEvidence(evidence string) string {
	if evidence == "" {
		return ""
	}
	evidence = awsKeyRegex.ReplaceAllString(evidence, "AKIA[REDACTED_AWS_KEY]")
	evidence = jwtTokenRegex.ReplaceAllString(evidence, "eyJ[REDACTED_JWT]")
	evidence = authHeaderRegex.ReplaceAllString(evidence, "${1}[REDACTED_TOKEN]")
	return evidence
}

// ValidateFinding runs a single finding through the 7-Check Readiness Gate.
func (v *Validator) ValidateFinding(ctx context.Context, f *findings.Finding) *ValidatedFinding {
	vf := &ValidatedFinding{
		Finding:     f,
		Status:      StatusVerified,
		GateResults: make([]GateResult, 0, 7),
	}

	evidenceBytes := []byte(f.Evidence + "\n" + f.Response)

	// --- Gate 1: Scope Verification ---
	inScope := true
	if v.Scope != nil {
		targetHost := f.Target
		if strings.HasPrefix(targetHost, "http://") || strings.HasPrefix(targetHost, "https://") {
			inScope = v.Scope.IsURLInScope(targetHost)
		} else {
			inScope = v.Scope.IsInScope(targetHost)
		}
	}
	if !inScope {
		vf.GateResults = append(vf.GateResults, GateResult{
			GateID: 1,
			Name:   "Scope Verification",
			Passed: false,
			Reason: fmt.Sprintf("Target %s is outside permitted scope", f.Target),
		})
		vf.Status = StatusSuppressed
		vf.SuppressionWhy = "Target out of scope"
		return vf
	}
	vf.GateResults = append(vf.GateResults, GateResult{GateID: 1, Name: "Scope Verification", Passed: true})

	// --- Gate 2: Soft-404 / Baseline Diff ---
	// Heuristic: Check if response body is HTML when checking sensitive config/exposure endpoints
	lowerPath := strings.ToLower(f.Path)
	isExposure := strings.Contains(lowerPath, ".git") || strings.Contains(lowerPath, ".env") ||
		strings.Contains(lowerPath, ".ds_store") || strings.HasSuffix(lowerPath, ".bak") ||
		strings.HasSuffix(lowerPath, ".sql") || strings.HasSuffix(lowerPath, ".zip")

	if isExposure && IsHTMLContent(evidenceBytes) {
		vf.GateResults = append(vf.GateResults, GateResult{
			GateID: 2,
			Name:   "Soft-404 / Baseline Diff",
			Passed: false,
			Reason: "Endpoint returned HTML page / SPA fallback instead of raw file",
		})
		vf.Status = StatusSuppressed
		vf.SuppressionWhy = "Soft-404 false positive (HTML SPA fallback)"
		return vf
	}

	// Dynamic baseline hook if provided
	if v.BaselineChecker != nil {
		isSoft, err := v.BaselineChecker(ctx, f.Target)
		if err == nil && isSoft {
			vf.GateResults = append(vf.GateResults, GateResult{
				GateID: 2,
				Name:   "Soft-404 / Baseline Diff",
				Passed: false,
				Reason: "Server returns HTTP 200 for non-existent baseline paths",
			})
			vf.Status = StatusSuppressed
			vf.SuppressionWhy = "Soft-404 detected via baseline diff"
			return vf
		}
	}
	vf.GateResults = append(vf.GateResults, GateResult{GateID: 2, Name: "Soft-404 / Baseline Diff", Passed: true})

	// --- Gate 3: Content Signature Match ---
	if strings.Contains(lowerPath, ".git/head") {
		if !IsValidGitHEAD(evidenceBytes) {
			vf.GateResults = append(vf.GateResults, GateResult{
				GateID: 3,
				Name:   "Content Signature Match",
				Passed: false,
				Reason: ".git/HEAD does not contain valid ref: refs/heads/ or 40-hex commit hash",
			})
			vf.Status = StatusSuppressed
			vf.SuppressionWhy = "Invalid .git/HEAD signature"
			return vf
		}
	} else if strings.Contains(lowerPath, ".env") {
		if !IsValidDotENV(evidenceBytes) {
			vf.GateResults = append(vf.GateResults, GateResult{
				GateID: 3,
				Name:   "Content Signature Match",
				Passed: false,
				Reason: ".env file does not contain KEY=value assignments or matched HTML tags",
			})
			vf.Status = StatusSuppressed
			vf.SuppressionWhy = "Invalid .env signature"
			return vf
		}
	} else if strings.Contains(lowerPath, ".ds_store") {
		if !IsValidDSStore(evidenceBytes) {
			vf.GateResults = append(vf.GateResults, GateResult{
				GateID: 3,
				Name:   "Content Signature Match",
				Passed: false,
				Reason: ".DS_Store missing 4-byte magic header",
			})
			vf.Status = StatusSuppressed
			vf.SuppressionWhy = "Invalid .DS_Store binary signature"
			return vf
		}
	}
	vf.GateResults = append(vf.GateResults, GateResult{GateID: 3, Name: "Content Signature Match", Passed: true})

	// --- Gate 4: Impact Classification ---
	// Missing headers on static asset files (.png, .css, .woff) are informational and low impact
	isHeaderCheck := strings.Contains(strings.ToLower(f.CheckName), "header") ||
		strings.Contains(strings.ToLower(f.Title), "header") ||
		strings.Contains(strings.ToLower(f.Title), "hsts") ||
		strings.Contains(strings.ToLower(f.Title), "csp")

	if isHeaderCheck && IsStaticAssetPath(f.Path) {
		vf.GateResults = append(vf.GateResults, GateResult{
			GateID: 4,
			Name:   "Impact Classification",
			Passed: false,
			Reason: "Missing security headers on non-sensitive static asset path",
		})
		vf.Status = StatusNeedsManualReview
		vf.SuppressionWhy = "Low-impact static asset header absence"
	} else {
		vf.GateResults = append(vf.GateResults, GateResult{GateID: 4, Name: "Impact Classification", Passed: true})
	}

	// --- Gate 5: Evidence Completeness & Redaction ---
	f.Evidence = RedactEvidence(f.Evidence)
	f.Response = RedactEvidence(f.Response)
	f.Request = RedactEvidence(f.Request)

	hasEvidence := f.Evidence != "" || f.Response != "" || f.Request != ""
	if !hasEvidence {
		vf.GateResults = append(vf.GateResults, GateResult{
			GateID: 5,
			Name:   "Evidence Completeness",
			Passed: false,
			Reason: "Finding lacks request/response or extract evidence snippet",
		})
		if vf.Status == StatusVerified {
			vf.Status = StatusNeedsManualReview
			vf.SuppressionWhy = "Incomplete evidence snippet"
		}
	} else {
		vf.GateResults = append(vf.GateResults, GateResult{GateID: 5, Name: "Evidence Completeness", Passed: true})
	}

	// --- Gate 6: Deduplication & Root-Cause Placeholder ---
	// Handled across findings during batch grouping, passed here for individual evaluation
	vf.GateResults = append(vf.GateResults, GateResult{GateID: 6, Name: "Deduplication & Grouping", Passed: true})

	// --- Gate 7: Remediation Mapping ---
	if f.Remediation == "" || len(f.References) == 0 {
		info := LookupRemediation(f.CheckName, f.RuleID, f.Title)
		if info != nil {
			if f.Remediation == "" {
				f.Remediation = info.Remediation
			}
			if len(f.References) == 0 {
				f.References = info.References
			}
			if f.Impact == "" {
				f.Impact = fmt.Sprintf("%s / %s", info.CWE, info.OWASP)
			}
		}
	}

	if f.Remediation != "" && len(f.References) > 0 {
		vf.GateResults = append(vf.GateResults, GateResult{GateID: 7, Name: "Remediation Mapping", Passed: true})
	} else {
		vf.GateResults = append(vf.GateResults, GateResult{
			GateID: 7,
			Name:   "Remediation Mapping",
			Passed: false,
			Reason: "Finding does not have remediation or CWE/OWASP references",
		})
		if vf.Status == StatusVerified {
			vf.Status = StatusNeedsManualReview
			vf.SuppressionWhy = "Missing remediation guidance"
		}
	}

	return vf
}

// GroupKey generates a grouping key for finding aggregation (Target, CheckName, RuleID, Severity).
func GroupKey(f *findings.Finding) string {
	targetHost := f.Target
	if u, err := url.Parse(f.Target); err == nil && u.Host != "" {
		targetHost = u.Host
	}
	return fmt.Sprintf("%s:%s:%s:%s", targetHost, f.CheckName, f.RuleID, f.Severity)
}

// ValidateAndGroup processes a collection of raw findings through the 7-Check Readiness Gate
// and groups duplicate misconfigurations across multiple paths on the same host.
func (v *Validator) ValidateAndGroup(ctx context.Context, rawList []*findings.Finding) []*ValidatedFinding {
	var individual []*ValidatedFinding
	for _, raw := range rawList {
		vf := v.ValidateFinding(ctx, raw)
		individual = append(individual, vf)
	}

	// Group identical misconfigurations across multiple paths on the same host (Gate 6)
	groups := make(map[string]*ValidatedFinding)
	var orderedKeys []string

	for _, vf := range individual {
		key := GroupKey(vf.Finding)
		if existing, found := groups[key]; found {
			// Merge path into existing finding
			if vf.Finding.Path != "" {
				existing.AffectedPaths = appendUnique(existing.AffectedPaths, vf.Finding.Path)
			}
		} else {
			if vf.Finding.Path != "" {
				vf.AffectedPaths = []string{vf.Finding.Path}
			}
			groups[key] = vf
			orderedKeys = append(orderedKeys, key)
		}
	}

	var results []*ValidatedFinding
	for _, key := range orderedKeys {
		results = append(results, groups[key])
	}

	return results
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
