package triage

import (
	"strings"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

// Hard-rule identifiers persisted in triage.json. These are code, not model
// output: they exist so a small local model cannot silently suppress a
// high-signal finding.
const (
	// RuleVerifiedVerdict fires when the 7-Check gate said Verified.
	RuleVerifiedVerdict = "gate_verdict_verified"
	// RuleHighSeverity fires for critical/high findings.
	RuleHighSeverity = "severity_critical_or_high"
	// RuleFirstCWEOccurrence fires for the first finding of a new CWE class in
	// the workspace, so novel bug classes survive an over-eager ranker.
	RuleFirstCWEOccurrence = "first_cwe_occurrence"
)

// RuleContext is the deterministic context required to evaluate hard rules.
type RuleContext struct {
	GateStatus         validate.ValidationStatus
	Severity           findings.Severity
	CWE                string
	FirstOccurrenceCWE bool
}

// ApplyHardRules post-processes a model verdict with deterministic overrides.
//
// The only override direction is likely_false -> needs_human. The layer can
// protect a finding from suppression, but it can never promote a finding to
// likely_true and it can never change the gate's verdict.
func ApplyHardRules(v *Verdict, rc RuleContext) {
	if v == nil || v.Classification != LikelyFalse {
		return
	}

	var applied []string
	if rc.GateStatus == validate.StatusVerified {
		applied = append(applied, RuleVerifiedVerdict)
	}
	if rc.Severity == findings.SeverityCritical || rc.Severity == findings.SeverityHigh {
		applied = append(applied, RuleHighSeverity)
	}
	if rc.FirstOccurrenceCWE && rc.CWE != "" {
		applied = append(applied, RuleFirstCWEOccurrence)
	}
	if len(applied) == 0 {
		return
	}

	v.Classification = NeedsHuman
	v.HardRuleOverrides = applied
	if v.Confidence < minOverrideConfidence {
		v.Confidence = minOverrideConfidence
	}
	if v.Source == "llm" {
		v.Source = "llm+hard_rule"
	}
	if !strings.Contains(v.Rationale, "Deterministic rule") {
		v.Rationale = strings.TrimSpace(v.Rationale +
			" Deterministic rule overrode likely_false: the finding needs human review.")
	}
	v.Rationale = truncate(v.Rationale, maxRationaleChars)
}

// HardRuleDocumentation describes the override layer for CLI help and docs.
func HardRuleDocumentation() string {
	return strings.Join([]string{
		"The deterministic override layer can only turn likely_false into needs_human:",
		"  1. " + RuleVerifiedVerdict + ": the 7-Check gate returned Verified.",
		"  2. " + RuleHighSeverity + ": severity is critical or high.",
		"  3. " + RuleFirstCWEOccurrence + ": first occurrence of this CWE in the workspace.",
		"It never promotes a finding, never alters gate verdicts and never runs inside the model.",
	}, "\n")
}
