package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

// GenerateMarkdown creates a structured, professional Markdown report from validated findings.
func GenerateMarkdown(target string, list []*validate.ValidatedFinding) string {
	var b strings.Builder

	var verified, manual, suppressed int
	sevCount := map[findings.Severity]int{}

	for _, vf := range list {
		switch vf.Status {
		case validate.StatusVerified:
			verified++
			sevCount[vf.Finding.Severity]++
		case validate.StatusNeedsManualReview:
			manual++
		case validate.StatusSuppressed:
			suppressed++
		}
	}

	b.WriteString(fmt.Sprintf("# scoutr Security Posture Report — %s\n\n", target))
	b.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().Format("2006-01-02 15:04:05 MST")))
	b.WriteString(fmt.Sprintf("**Target:** `%s`  \n", target))
	b.WriteString(fmt.Sprintf("**Validation Status:** %d Verified | %d Needs Manual Review | %d Suppressed\n\n",
		verified, manual, suppressed))

	b.WriteString("## Executive Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("| :--- | :--- |\n")
	b.WriteString(fmt.Sprintf("| 🟣 Critical | %d |\n", sevCount[findings.SeverityCritical]))
	b.WriteString(fmt.Sprintf("| 🔴 High | %d |\n", sevCount[findings.SeverityHigh]))
	b.WriteString(fmt.Sprintf("| 🟠 Medium | %d |\n", sevCount[findings.SeverityMedium]))
	b.WriteString(fmt.Sprintf("| 🔵 Low | %d |\n", sevCount[findings.SeverityLow]))
	b.WriteString(fmt.Sprintf("| ⚪ Info | %d |\n\n", sevCount[findings.SeverityInfo]))

	// Verified Findings
	b.WriteString("## Verified Findings\n\n")
	if verified == 0 {
		b.WriteString("*No verified security issues found.* \n\n")
	} else {
		for i, vf := range list {
			if vf.Status != validate.StatusVerified {
				continue
			}
			f := vf.Finding
			b.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, strings.ToUpper(string(f.Severity)), f.Title))
			b.WriteString(fmt.Sprintf("- **Rule / ID:** `%s` (`%s`)\n", f.RuleID, f.ID))
			b.WriteString(fmt.Sprintf("- **Target:** `%s`\n", f.Target))
			if len(vf.AffectedPaths) > 0 {
				b.WriteString(fmt.Sprintf("- **Affected Endpoints:** `%s`\n", strings.Join(vf.AffectedPaths, "`, `")))
			} else if f.Path != "" {
				b.WriteString(fmt.Sprintf("- **Path:** `%s`\n", f.Path))
			}
			b.WriteString(fmt.Sprintf("- **Impact:** %s\n\n", f.Impact))

			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("**Remediation Guidance:**\n%s\n\n", f.Remediation))
			}

			if len(f.References) > 0 {
				b.WriteString("**References:**\n")
				for _, ref := range f.References {
					b.WriteString(fmt.Sprintf("- <%s>\n", ref))
				}
				b.WriteString("\n")
			}

			if f.Evidence != "" || f.Response != "" {
				b.WriteString("**Evidence Snippet:**\n```http\n")
				if f.Request != "" {
					b.WriteString(f.Request + "\n\n")
				}
				if f.Evidence != "" {
					b.WriteString(f.Evidence)
				} else {
					b.WriteString(f.Response)
				}
				b.WriteString("\n```\n\n")
			}
		}
	}

	// Needs Manual Review
	if manual > 0 {
		b.WriteString("## Findings Requiring Manual Review\n\n")
		for _, vf := range list {
			if vf.Status != validate.StatusNeedsManualReview {
				continue
			}
			f := vf.Finding
			b.WriteString(fmt.Sprintf("- **%s** on `%s` (%s): %s\n", f.Title, f.Target, f.Path, vf.SuppressionWhy))
		}
		b.WriteString("\n")
	}

	return b.String()
}
