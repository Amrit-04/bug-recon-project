// Package draft implements scoutr's Tier 2 report drafting layer.
//
// A draft is produced from two inputs only:
//  1. validated_findings.json — the deterministic source of truth
//  2. triage.json            — used to decide WHAT gets drafted and in what order
//
// Hard constraints enforced here:
//   - The evidence section is rendered by this package from the finding fields,
//     never by the model, so evidence cannot be invented.
//   - Every model-produced string is passed through a URL/CWE/CVSS guard; any
//     claim that is not grounded in the evidence becomes NEEDS_HUMAN_INPUT.
//   - Drafts are written under reports/drafts/ and are never marked
//     submission-ready. Only `scoutr submit --require-approval` can do that.
package draft

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
)

// NeedsHumanInput is the mandatory placeholder for anything the model cannot
// ground in the supplied evidence.
const NeedsHumanInput = "NEEDS_HUMAN_INPUT"

// SystemPrompt is the Tier 2 drafting contract. It forbids invention and
// forbids any submission action.
const SystemPrompt = `You draft a security report for a HUMAN reviewer. You are not submitting anything.

Input: one JSON object with "evidence" (authoritative, redacted), "triage" (a
non-authoritative ranking) and "technology".

Return STRICT JSON only, with exactly these keys:
{
  "title": "short report title",
  "summary": "2-4 sentences describing what was observed",
  "reproduction_steps": ["ordered", "steps"],
  "impact": "impact assessment",
  "remediation": "remediation guidance",
  "cvss_vector": "CVSS:3.1/... or NEEDS_HUMAN_INPUT",
  "cwe": "CWE-<number> or NEEDS_HUMAN_INPUT",
  "missing_fields": ["fields you could not fill from evidence"]
}

Absolute rules:
  - Use ONLY facts present in "evidence". Do not invent URLs, hosts, parameters,
    status codes, response bodies, screenshots, headers, technologies, users or
    business impact.
  - Reproduction steps must be derived from the evidence fields (evidence,
    request_redacted, response_redacted, target, path, matched_template_id).
  - If a field cannot be filled from evidence, use "NEEDS_HUMAN_INPUT"
    (in the array, a single entry "NEEDS_HUMAN_INPUT").
  - Never claim a test was run, a payload was sent, or a third party was
    contacted unless the evidence shows it.
  - Never output credentials, tokens or personal data; evidence is already
    redacted, keep it that way.
  - Do not output markdown or prose outside the JSON object.`

// Request is one finding plus its triage context.
type Request struct {
	Finding          *validate.ValidatedFinding
	Verdict          triage.Verdict
	Technology       []string
	MaxEvidenceChars int
}

// sections is the parsed model output.
type sections struct {
	Title             string   `json:"title"`
	Summary           string   `json:"summary"`
	ReproductionSteps []string `json:"reproduction_steps"`
	Impact            string   `json:"impact"`
	Remediation       string   `json:"remediation"`
	CVSSVector        string   `json:"cvss_vector"`
	CWE               string   `json:"cwe"`
	MissingFields     []string `json:"missing_fields"`
}

// Draft is a rendered, review-ready Markdown document.
type Draft struct {
	FindingID      string                    `json:"finding_id"`
	Title          string                    `json:"title"`
	FileName       string                    `json:"file_name"`
	Classification triage.Classification     `json:"triage_classification"`
	GateVerdict    validate.ValidationStatus `json:"gate_verdict"`
	Markdown       string                    `json:"-"`
	MissingFields  []string                  `json:"missing_fields,omitempty"`
	GuardWarnings  []string                  `json:"guard_warnings,omitempty"`
	Provider       string                    `json:"provider"`
}

// Builder produces drafts with an optional model client.
type Builder struct {
	// Client may be nil: the draft is then assembled deterministically with
	// NEEDS_HUMAN_INPUT placeholders for narrative fields.
	Client   triage.Client
	Model    string
	MaxChars int
}

// Build renders one draft.
func (b *Builder) Build(ctx context.Context, req Request) (*Draft, error) {
	if req.Finding == nil || req.Finding.Finding == nil {
		return nil, fmt.Errorf("draft request is missing a finding")
	}
	f := req.Finding.Finding
	maxChars := req.MaxEvidenceChars
	if maxChars <= 0 {
		maxChars = b.MaxChars
	}

	// Deterministic baseline: everything the gate already knows.
	sec := sections{
		Title:             f.Title,
		Summary:           NeedsHumanInput,
		ReproductionSteps: []string{NeedsHumanInput},
		Impact:            orPlaceholder(f.Impact),
		Remediation:       orPlaceholder(f.Remediation),
		CVSSVector:        NeedsHumanInput,
		CWE:               orPlaceholder(triage.ExtractCWE(f)),
	}

	d := &Draft{
		FindingID:      f.ID,
		Title:          f.Title,
		FileName:       FileName(f.ID),
		Classification: req.Verdict.Classification,
		GateVerdict:    req.Finding.Status,
		Provider:       "deterministic",
	}

	if b.Client != nil {
		d.Provider = b.Client.Name()
		modelSec, missing, err := b.fromModel(ctx, req, maxChars)
		if err != nil {
			// Model failure degrades to the deterministic draft: never to a
			// fabricated one.
			d.GuardWarnings = append(d.GuardWarnings, "model drafting failed: "+err.Error())
			d.MissingFields = append(d.MissingFields, "summary", "reproduction_steps", "cvss_vector")
		} else {
			merged := mergeSections(sec, modelSec)
			sec = merged
			d.MissingFields = missing
		}
	} else {
		d.MissingFields = []string{"summary", "reproduction_steps", "cvss_vector"}
	}

	// Guard model text against claims that are not in the evidence bundle.
	warnings := guardSections(&sec, req)
	d.GuardWarnings = append(d.GuardWarnings, warnings...)

	// The guarded title is the single value used for both the manifest and the
	// H1 heading: the model never gets a second, unchecked path into the file.
	d.Title = sec.Title

	if cleaned := sanitizeMissingFields(d.MissingFields); len(cleaned) != len(d.MissingFields) {
		d.GuardWarnings = append(d.GuardWarnings, "missing_fields contained entries this renderer does not accept; they were dropped")
		d.MissingFields = cleaned
	}

	// Warnings are rendered into the draft too, so they must not carry invented
	// infrastructure either (a model failure string can quote model output).
	allowed := triage.EvidenceHosts(f)
	for i, w := range d.GuardWarnings {
		d.GuardWarnings[i], _ = triage.GuardURLs(w, allowed, "[unverified URL removed]")
	}

	d.Markdown = render(req, &sec, d)
	return d, nil
}

// fromModel performs the single drafting call and parses the JSON contract.
func (b *Builder) fromModel(ctx context.Context, req Request, maxChars int) (sections, []string, error) {
	evidence := triage.BuildEvidence(req.Finding, req.Technology, maxChars)
	payload := map[string]any{
		"evidence":   evidence,
		"triage":     req.Verdict,
		"technology": req.Technology,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return sections{}, nil, fmt.Errorf("marshal drafting payload: %w", err)
	}

	resp, err := b.Client.Complete(ctx, triage.CompletionRequest{
		System: SystemPrompt,
		User:   "Draft the report sections for this finding. Return JSON only.\n\nINPUT:\n" + string(raw),
	})
	if err != nil {
		return sections{}, nil, err
	}

	parsed, err := parseSections(resp.Content)
	if err != nil {
		return sections{}, nil, err
	}
	return parsed, parsed.MissingFields, nil
}

// parseSections accepts a bare JSON object or a fenced one and rejects output
// that is not a JSON object.
func parseSections(content string) (sections, error) {
	var out sections
	cleaned := extractJSONObject(content)
	if cleaned == "" {
		return out, fmt.Errorf("model returned no JSON object")
	}
	if err := json.Unmarshal([]byte(cleaned), &out); err != nil {
		return out, fmt.Errorf("model output is not valid JSON: %w", err)
	}
	return out, nil
}

func extractJSONObject(content string) string {
	s := strings.TrimSpace(content)
	if idx := strings.Index(s, "```"); idx != -1 {
		s = s[idx+3:]
		s = strings.TrimPrefix(s, "json")
		s = strings.TrimPrefix(s, "JSON")
		if end := strings.Index(s, "```"); end != -1 {
			s = s[:end]
		}
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	return s[start : end+1]
}

// mergeSections keeps deterministic evidence-derived values when the model left
// a field empty or placeholder.
func mergeSections(base, model sections) sections {
	out := base
	if v := strings.TrimSpace(model.Title); v != "" {
		out.Title = v
	}
	if v := strings.TrimSpace(model.Summary); v != "" {
		out.Summary = v
	}
	if len(model.ReproductionSteps) > 0 {
		out.ReproductionSteps = model.ReproductionSteps
	}
	if v := strings.TrimSpace(model.Impact); v != "" {
		out.Impact = v
	}
	if v := strings.TrimSpace(model.Remediation); v != "" {
		out.Remediation = v
	}
	if v := strings.TrimSpace(model.CVSSVector); v != "" {
		out.CVSSVector = v
	}
	if v := strings.TrimSpace(model.CWE); v != "" {
		out.CWE = v
	}
	out.MissingFields = model.MissingFields
	return out
}

var (
	cweRegex = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
)

// missingFieldNames is the only vocabulary the renderer accepts in the
// "Fields Requiring Human Input" list. Model output is never rendered verbatim
// into the report body, so an unknown name is dropped rather than printed.
var missingFieldNames = map[string]bool{
	"title":              true,
	"summary":            true,
	"reproduction_steps": true,
	"impact":             true,
	"remediation":        true,
	"cvss_vector":        true,
	"cwe":                true,
	"evidence":           true,
	"affected_asset":     true,
	"severity":           true,
}

// sanitizeMissingFields lowercases, de-duplicates and whitelists field names.
func sanitizeMissingFields(fields []string) []string {
	var out []string
	seen := make(map[string]bool, len(fields))
	for _, raw := range fields {
		name := strings.ToLower(strings.TrimSpace(raw))
		if !missingFieldNames[name] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// collapseWhitespace reduces model text to a single line so it cannot inject
// headings, list items or table rows into the rendered Markdown.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// guardSections rewrites any model claim that is not grounded in the evidence.
// It returns human-readable warnings for the draft header.
func guardSections(sec *sections, req Request) []string {
	f := req.Finding.Finding
	allowedHosts := triage.EvidenceHosts(f)

	var warnings []string
	check := func(field, value string) string {
		out, replaced := triage.GuardURLs(value, allowedHosts, NeedsHumanInput)
		if replaced {
			warnings = append(warnings, fmt.Sprintf("%s referenced a URL absent from the evidence and was replaced with %s", field, NeedsHumanInput))
		}
		return out
	}

	// The title becomes the H1 heading and a manifest cell, so it must be one
	// guarded line with no placeholder or fenced content in it.
	title := collapseWhitespace(check("title", sec.Title))
	if title == "" || strings.Contains(title, NeedsHumanInput) || len(title) > 200 || strings.Contains(title, "```") {
		warnings = append(warnings, "title was empty, ungrounded or unusable and was replaced with the finding's own title")
		title = collapseWhitespace(f.Title)
	}
	if title == "" {
		title = "Untitled finding"
	}
	sec.Title = title

	sec.Summary = check("summary", sec.Summary)
	sec.Impact = check("impact", sec.Impact)
	sec.Remediation = check("remediation", sec.Remediation)

	for i, step := range sec.ReproductionSteps {
		guarded := check(fmt.Sprintf("reproduction_steps[%d]", i), step)
		if guarded != step {
			// A step anchored on an invented URL is useless; make the gap explicit.
			guarded = NeedsHumanInput
		}
		if strings.Contains(guarded, "```") {
			guarded = NeedsHumanInput
			warnings = append(warnings, fmt.Sprintf("reproduction_steps[%d] contained fenced content", i))
		}
		sec.ReproductionSteps[i] = guarded
	}
	if len(sec.ReproductionSteps) == 0 {
		sec.ReproductionSteps = []string{NeedsHumanInput}
	}

	if sec.CWE != "" && sec.CWE != NeedsHumanInput && !cweRegex.MatchString(strings.ToUpper(strings.TrimSpace(sec.CWE))) {
		warnings = append(warnings, "cwe did not match CWE-<number> and was replaced with "+NeedsHumanInput)
		sec.CWE = NeedsHumanInput
	}
	if sec.CVSSVector != "" && sec.CVSSVector != NeedsHumanInput && !validCVSS(sec.CVSSVector) {
		warnings = append(warnings, "cvss_vector was not a CVSS 3.0/3.1 base vector and was replaced with "+NeedsHumanInput)
		sec.CVSSVector = NeedsHumanInput
	}
	if strings.TrimSpace(sec.Summary) == "" {
		sec.Summary = NeedsHumanInput
	}
	if strings.TrimSpace(sec.Impact) == "" {
		sec.Impact = NeedsHumanInput
	}
	if strings.TrimSpace(sec.Remediation) == "" {
		sec.Remediation = NeedsHumanInput
	}
	return warnings
}

// validCVSS validates a CVSS v3.0/v3.1 base vector shape without scoring it.
func validCVSS(vector string) bool {
	v := strings.TrimSpace(vector)
	if !strings.HasPrefix(v, "CVSS:3.0/") && !strings.HasPrefix(v, "CVSS:3.1/") {
		return false
	}
	for _, metric := range []string{"AV:", "AC:", "PR:", "UI:", "S:", "C:", "I:", "A:"} {
		if !strings.Contains(v, metric) {
			return false
		}
	}
	return true
}

func orPlaceholder(s string) string {
	if strings.TrimSpace(s) == "" {
		return NeedsHumanInput
	}
	return strings.TrimSpace(s)
}

// FileName derives a filesystem-safe draft file name from a finding ID.
func FileName(findingID string) string {
	sanitised := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, findingID)
	sanitised = strings.Trim(sanitised, "-")
	if sanitised == "" {
		sanitised = "finding"
	}
	if len(sanitised) > 80 {
		sanitised = sanitised[:80]
	}
	return strings.ToLower(sanitised) + ".md"
}

// render assembles the final Markdown. Evidence is inserted exclusively from the
// finding itself, so it can never be fabricated by the model.
func render(req Request, sec *sections, d *Draft) string {
	f := req.Finding.Finding
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# %s\n\n", d.Title))
	b.WriteString("> **Tier 2 draft — human review required.**\n")
	b.WriteString(fmt.Sprintf("> Triage classification: `%s` (confidence %d, source %s)\n",
		req.Verdict.Classification, req.Verdict.Confidence, req.Verdict.Source))
	b.WriteString(fmt.Sprintf("> 7-Check gate verdict: `%s`\n", req.Finding.Status))
	b.WriteString("> This file is **not** submission-ready. Run `scoutr submit --require-approval` and type `APPROVE` to queue it.\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString(sec.Summary + "\n\n")

	b.WriteString("## Affected Asset\n\n")
	b.WriteString(fmt.Sprintf("- **Target:** `%s`\n", f.Target))
	if f.Path != "" {
		b.WriteString(fmt.Sprintf("- **Path:** `%s`\n", f.Path))
	}
	if len(req.Finding.AffectedPaths) > 0 {
		b.WriteString(fmt.Sprintf("- **Affected endpoints:** `%s`\n", strings.Join(req.Finding.AffectedPaths, "`, `")))
	}
	if len(req.Technology) > 0 {
		b.WriteString(fmt.Sprintf("- **Technology:** %s\n", strings.Join(req.Technology, ", ")))
	}
	b.WriteString(fmt.Sprintf("- **Severity:** %s | **Confidence:** %s\n\n", strings.ToUpper(string(f.Severity)), f.Confidence))

	b.WriteString("## Reproduction Steps\n\n")
	steps := sec.ReproductionSteps
	if len(steps) == 1 && steps[0] == NeedsHumanInput {
		b.WriteString(NeedsHumanInput + " — the evidence bundle does not contain enough detail to derive steps.\n\n")
	} else {
		for i, step := range steps {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Evidence (verbatim from the validation gate)\n\n")
	hasEvidence := false
	if f.Request != "" {
		hasEvidence = true
		b.WriteString("### Request (redacted)\n\n```http\n" + f.Request + "\n```\n\n")
	}
	if f.Response != "" {
		hasEvidence = true
		b.WriteString("### Response (redacted)\n\n```http\n" + f.Response + "\n```\n\n")
	}
	if f.Evidence != "" {
		hasEvidence = true
		b.WriteString("### Matched evidence\n\n```\n" + f.Evidence + "\n```\n\n")
	}
	if !hasEvidence {
		b.WriteString(NeedsHumanInput + " — no request/response snippet was captured.\n\n")
	}
	b.WriteString(fmt.Sprintf("- **Check:** `%s`\n- **Matched template / rule:** `%s`\n- **Finding ID:** `%s`\n\n",
		f.CheckName, orPlaceholder(f.RuleID), f.ID))

	b.WriteString("## Impact Assessment\n\n" + sec.Impact + "\n\n")
	b.WriteString("## Remediation Guidance\n\n" + sec.Remediation + "\n\n")
	b.WriteString("## CVSS\n\n`" + orPlaceholder(sec.CVSSVector) + "`\n\n")
	b.WriteString("## CWE\n\n`" + orPlaceholder(sec.CWE) + "`\n\n")

	if len(f.References) > 0 {
		refs := append([]string{}, f.References...)
		sort.Strings(refs)
		b.WriteString("## References\n\n")
		for _, r := range refs {
			b.WriteString("- <" + r + ">\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Triage Notes (non-authoritative)\n\n")
	b.WriteString(fmt.Sprintf("- Classification: `%s`\n", req.Verdict.Classification))
	if req.Verdict.Rationale != "" {
		b.WriteString("- Rationale: " + req.Verdict.Rationale + "\n")
	}
	if req.Verdict.NextManualTest != "" {
		b.WriteString("- Suggested manual test: " + req.Verdict.NextManualTest + "\n")
	}
	if len(req.Verdict.HardRuleOverrides) > 0 {
		b.WriteString("- Deterministic overrides applied: `" + strings.Join(req.Verdict.HardRuleOverrides, "`, `") + "`\n")
	}
	b.WriteString("\n")

	if len(d.MissingFields) > 0 {
		b.WriteString("## Fields Requiring Human Input\n\n")
		for _, m := range d.MissingFields {
			b.WriteString("- " + m + "\n")
		}
		b.WriteString("\n")
	}
	if len(d.GuardWarnings) > 0 {
		b.WriteString("## Draft Guard Warnings\n\n")
		for _, w := range d.GuardWarnings {
			b.WriteString("- " + w + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("*Generated by scoutr Tier 2 drafting. The 7-Check gate remains the authority for ")
	b.WriteString("Verified vs. NeedsManualReview, and no finding is submission-ready without a human APPROVE.*\n")
	return b.String()
}
