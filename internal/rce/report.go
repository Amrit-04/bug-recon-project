package rce

import (
	"fmt"
	"strings"
	"time"
)

// GenerateReport generates an in-depth, submission-ready Markdown research report.
func GenerateReport(target string, scopeRef string, candidates []*RCECandidate, advisories []Advisory) string {
	var b strings.Builder

	now := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	b.WriteString("# Scoutr RCE Research and Attack Surface Report\n\n")
	b.WriteString(fmt.Sprintf("**Target:** `%s`  \n", target))
	b.WriteString(fmt.Sprintf("**Scope Reference:** `%s`  \n", scopeRef))
	b.WriteString(fmt.Sprintf("**Generated At:** %s  \n", now))
	b.WriteString("**Research Framework:** Scoutr Phase 4 Application-Aware RCE Engine  \n\n")
	b.WriteString("---\n\n")

	// 1. Executive Summary
	total := len(candidates)
	var validated, corroborated, needsReview, candidatesOnly int
	for _, c := range candidates {
		switch c.ValidationStatus {
		case StatusValidated:
			validated++
		case StatusCorroborated:
			corroborated++
		case StatusNeedsManualReview:
			needsReview++
		default:
			candidatesOnly++
		}
	}

	b.WriteString("## 1. Executive Summary\n\n")
	b.WriteString("This report presents the findings of an application-aware Remote Code Execution (RCE) research evaluation conducted using Scoutr. ")
	b.WriteString("The engine systematically cataloged execution attack surfaces, correlated backend technologies against public vulnerability advisories, evaluated multi-step processing chains, and performed controlled non-destructive validation.\n\n")

	b.WriteString("| Metric | Count | Description |\n")
	b.WriteString("|---|---|---|\n")
	b.WriteString(fmt.Sprintf("| **Total Candidates Discovered** | %d | Endpoints with execution attack surface features |\n", total))
	b.WriteString(fmt.Sprintf("| **Validated RCE Findings** | %d | Confirmed via controlled marker evaluation |\n", validated))
	b.WriteString(fmt.Sprintf("| **Corroborated Hypotheses** | %d | Corroborated by reachable advisories/chains |\n", corroborated))
	b.WriteString(fmt.Sprintf("| **Needs Manual Review** | %d | Probes inconclusive or manual check required |\n", needsReview))
	b.WriteString(fmt.Sprintf("| **Attack Surface Candidates** | %d | Prioritized for further investigation |\n\n", candidatesOnly))

	// 2. Candidate Inventory & Prioritisation
	b.WriteString("## 2. Attack Surface Candidate Queue\n\n")
	if total == 0 {
		b.WriteString("No RCE attack surface candidates identified in current endpoint inventory.\n\n")
	} else {
		b.WriteString("| Priority | Category | Method | Route | Confidence | Status |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, c := range candidates {
			b.WriteString(fmt.Sprintf("| **%d/100** | `%s` | `%s` | `%s` | `%s` | `%s` |\n",
				c.PriorityScore, c.Category, c.HTTPMethod, c.Route, c.Confidence, c.ValidationStatus))
		}
		b.WriteString("\n")
	}

	// 3. Processing Chains
	b.WriteString("## 3. Discovered Multi-Step Processing Chains\n\n")
	chainMap := make(map[string]ProcessingChain)
	for _, c := range candidates {
		for _, ch := range c.AssociatedChains {
			chainMap[ch.ChainID] = ch
		}
	}

	if len(chainMap) == 0 {
		b.WriteString("No multi-step processing chains identified.\n\n")
	} else {
		for _, ch := range chainMap {
			b.WriteString(fmt.Sprintf("### Chain: %s\n\n", ch.Name))
			b.WriteString(fmt.Sprintf("%s\n\n", ch.Description))
			b.WriteString("| Step | Route | Method | Role | Data Flow |\n")
			b.WriteString("|---|---|---|---|---|\n")
			for i, st := range ch.Steps {
				b.WriteString(fmt.Sprintf("| %d | `%s` | `%s` | `%s` | %s |\n",
					i+1, st.Route, st.Method, st.Role, st.DataFlow))
			}
			b.WriteString("\n")
		}
	}

	// 4. Detailed Candidate Hypotheses & Validation Evidence
	b.WriteString("## 4. Detailed Candidate Hypotheses & Evidence\n\n")
	for i, c := range candidates {
		b.WriteString(fmt.Sprintf("### 4.%d %s — `%s %s`\n\n", i+1, c.FeatureType, c.HTTPMethod, c.Route))
		b.WriteString(fmt.Sprintf("- **Candidate ID:** `%s`\n", c.ID))
		b.WriteString(fmt.Sprintf("- **Execution Risk Category:** `%s`\n", c.Category))
		b.WriteString(fmt.Sprintf("- **Priority Score:** %d/100\n", c.PriorityScore))
		b.WriteString(fmt.Sprintf("- **Validation Status:** `%s`\n", c.ValidationStatus))
		b.WriteString(fmt.Sprintf("- **Suspected Execution Sink:** %s\n\n", c.SuspectedSink))

		b.WriteString("#### Hypothesis\n\n")
		b.WriteString(fmt.Sprintf("%s\n\n", c.Hypothesis))

		b.WriteString("#### Score Breakdown\n\n")
		for _, exp := range c.ScoreBreakdown.Explanations {
			b.WriteString(fmt.Sprintf("- %s\n", exp))
		}
		b.WriteString("\n")

		if len(c.EvidenceSignals) > 0 {
			b.WriteString("#### Evidence Signals\n\n")
			for _, sig := range c.EvidenceSignals {
				b.WriteString(fmt.Sprintf("- %s\n", sig))
			}
			b.WriteString("\n")
		}

		if len(c.MatchingAdvisories) > 0 {
			b.WriteString("#### Matching CVE / Public Advisories\n\n")
			for _, m := range c.MatchingAdvisories {
				b.WriteString(fmt.Sprintf("- **%s:** %s  \n", m.Advisory.ID, m.Advisory.Title))
				b.WriteString(fmt.Sprintf("  - *Progression Tier:* `%s`\n", m.ProgressionTier))
				b.WriteString(fmt.Sprintf("  - *Reachability Assessment:* %s\n", m.ReachabilityReason))
			}
			b.WriteString("\n")
		}

		if len(c.ValidationAttempts) > 0 {
			b.WriteString("#### Validation Attempts & Verification Evidence\n\n")
			for _, att := range c.ValidationAttempts {
				b.WriteString(fmt.Sprintf("##### Attempt: `%s` (Profile: `%s`)\n\n", att.AttemptID, att.Profile))
				b.WriteString(fmt.Sprintf("- **Timestamp:** %s\n", att.Timestamp.Format("2006-01-02 15:04:05 UTC")))
				b.WriteString(fmt.Sprintf("- **Correlation ID:** `%s`\n", att.CorrelationID))
				b.WriteString(fmt.Sprintf("- **Execution Confirmed:** `%t` (Marker Found: `%t`, Reflection Excluded: `%t`)\n",
					att.ExecutionConfirmed, att.MarkerFound, att.ReflectionExcluded))
				b.WriteString(fmt.Sprintf("- **Notes:** %s\n\n", att.Notes))

				if att.PositiveRequestSent != "" {
					b.WriteString("```http\n# Positive Probe Sent\n" + att.PositiveRequestSent + "\n```\n\n")
				}
				if att.PositiveResponseObserved != "" {
					b.WriteString("```http\n# Positive Response Observed\n" + att.PositiveResponseObserved + "\n```\n\n")
				}
			}
		}

		// Reproduction steps
		b.WriteString("#### Reproduction Instructions\n\n")
		b.WriteString("To reproduce this test manually in an authorized environment:\n\n")
		b.WriteString("```bash\n")
		b.WriteString(fmt.Sprintf("curl -i -s -k -X %s '%s%s' \\\n", c.HTTPMethod, c.Origin, c.Route))
		b.WriteString("  -H 'User-Agent: Scoutr-Security-Research/1.0' \\\n")
		b.WriteString("  -H 'X-Scoutr-Correlate: reproduction-test'\n")
		b.WriteString("```\n\n")

		// Remediation Guidance
		b.WriteString("#### Remediation Guidance\n\n")
		switch c.Category {
		case CategoryCommandInjection:
			b.WriteString("- Avoid constructing shell command lines with string concatenation. Use parameterized system calls (e.g. `exec.Command` in Go, `subprocess.run([...])` without `shell=True` in Python).\n")
			b.WriteString("- Enforce strict positive input validation allowlisting on all network/diagnostic parameters.\n")
		case CategorySSTI:
			b.WriteString("- Never pass user-supplied strings directly to template rendering functions (e.g. `render_template_string`).\n")
			b.WriteString("- Utilize sandboxed template engines with dangerous attribute and method access disabled.\n")
		case CategoryFileProcessing:
			b.WriteString("- Keep image and document conversion utilities (ImageMagick, Ghostscript, LibreOffice) fully updated with security patches.\n")
			b.WriteString("- Run file parsing utilities in sandboxed containers with minimal OS privileges and disabled network egress.\n")
		case CategoryDeserialization:
			b.WriteString("- Avoid native deserialization of untrusted data (Java ObjectInputStream, Python pickle, PHP unserialize). Use safe data interchange formats such as JSON with strict schema validation.\n")
		case CategoryExpressionLanguage:
			b.WriteString("- Do not evaluate user-supplied expressions dynamically. Restrict evaluation contexts using secure AST visitors or allowlisted evaluation functions.\n")
		default:
			b.WriteString("- Implement defense-in-depth input sanitization and restrict system execution privileges.\n")
		}
		b.WriteString("\n---\n\n")
	}

	return b.String()
}
