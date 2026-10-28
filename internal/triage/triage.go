// Package triage is scoutr's Tier 2 ranking layer.
//
// It reads findings that have already been classified by the deterministic
// 7-Check Readiness Gate and asks a local model for a conservative ranking
// (likely_true / likely_false / needs_human) plus a rationale.
//
// Guarantees enforced by this package:
//   - The 7-Check gate remains the authority. Suppressed findings are never
//     sent to the model and triage never changes a gate verdict.
//   - The model never receives the scope file, the target inventory, secrets or
//     any tool-selection ability. Only redacted finding evidence is batched.
//   - A deterministic hard-rule layer (rules.go) can veto "likely_false".
//   - Failure of the model degrades to needs_human, never to suppression.
//   - The output (triage.json) is a separate artifact; it can only influence
//     report ordering, never report content.
package triage

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

// Classification is the closed set of triage verdicts.
type Classification string

const (
	// LikelyTrue means the supplied evidence strongly supports a real issue.
	LikelyTrue Classification = "likely_true"
	// LikelyFalse means the supplied evidence strongly suggests a non-issue.
	LikelyFalse Classification = "likely_false"
	// NeedsHuman means evidence is insufficient or ambiguous.
	NeedsHuman Classification = "needs_human"
)

const (
	// Version is the triage.json schema version.
	Version = "1.0"
	// DefaultBatchSize groups findings so a local model needs few calls.
	DefaultBatchSize = 12
	// MaxBatchSize bounds a single prompt.
	MaxBatchSize = 20
	// DefaultMaxEvidenceChars truncates each request/response field.
	DefaultMaxEvidenceChars = 4000

	maxRationaleChars = 400
	maxNextStepChars  = 300

	// minOverrideConfidence is the floor applied when a hard rule vetoes a
	// likely_false classification.
	minOverrideConfidence = 50
)

// LogFunc is a logging callback shared with the CLI.
type LogFunc func(format string, args ...any)

// Evidence is the only view of a finding the model is allowed to see.
type Evidence struct {
	FindingID    string                `json:"finding_id"`
	Title        string                `json:"title"`
	CheckName    string                `json:"check_name"`
	RuleID       string                `json:"matched_template_id,omitempty"`
	Target       string                `json:"target"`
	Path         string                `json:"path,omitempty"`
	Severity     string                `json:"severity"`
	Confidence   string                `json:"confidence"`
	GateVerdict  string                `json:"gate_verdict"`
	GateResults  []validate.GateResult `json:"gate_results,omitempty"`
	CWE          string                `json:"cwe,omitempty"`
	Technology   []string              `json:"technology,omitempty"`
	AffectedPath []string              `json:"affected_paths,omitempty"`
	Impact       string                `json:"impact,omitempty"`
	Evidence     string                `json:"evidence,omitempty"`
	Request      string                `json:"request_redacted,omitempty"`
	Response     string                `json:"response_redacted,omitempty"`
	Remediation  string                `json:"remediation,omitempty"`
	FirstCWE     bool                  `json:"first_occurrence_of_cwe,omitempty"`
}

// Verdict is the final, post-hard-rule judgement for one finding.
type Verdict struct {
	FindingID         string         `json:"finding_id"`
	Title             string         `json:"title"`
	Target            string         `json:"target"`
	Severity          string         `json:"severity"`
	GateVerdict       string         `json:"gate_verdict"`
	Classification    Classification `json:"classification"`
	Rationale         string         `json:"rationale"`
	Confidence        int            `json:"confidence"`
	NextManualTest    string         `json:"next_manual_test,omitempty"`
	Rank              int            `json:"rank"`
	Source            string         `json:"source"`
	HardRuleOverrides []string       `json:"hard_rule_overrides,omitempty"`
}

// Report is the triage.json document.
type Report struct {
	Version            string         `json:"version"`
	GeneratedAt        time.Time      `json:"generated_at"`
	Provider           string         `json:"provider"`
	Model              string         `json:"model"`
	BatchSize          int            `json:"batch_size"`
	Batches            int            `json:"batches"`
	Eligible           int            `json:"eligible_findings"`
	ExcludedSuppressed int            `json:"excluded_suppressed"`
	Counts             map[string]int `json:"counts"`
	LLMErrors          []string       `json:"llm_errors,omitempty"`
	Verdicts           []Verdict      `json:"verdicts"`
}

// Options configures a triage run.
type Options struct {
	Client           Client
	Model            string
	BatchSize        int
	MaxEvidenceChars int
	Log              LogFunc
}

// cweRegex extracts the CWE identifier the gate mapped onto a finding.
var cweRegex = regexp.MustCompile(`CWE-[0-9]+`)

// ExtractCWE returns the first CWE identifier found in the finding's impact,
// references or remediation text (the gate writes it into Impact).
func ExtractCWE(f *findings.Finding) string {
	if f == nil {
		return ""
	}
	candidates := []string{f.Impact, f.Remediation}
	candidates = append(candidates, f.References...)
	candidates = append(candidates, f.Title)
	for _, c := range candidates {
		if match := cweRegex.FindString(strings.ToUpper(c)); match != "" {
			return match
		}
	}
	return ""
}

// BuildEvidence converts a validated finding into the redacted evidence bundle
// the model is allowed to see.
func BuildEvidence(vf *validate.ValidatedFinding, technology []string, maxChars int) Evidence {
	f := vf.Finding
	if maxChars <= 0 {
		maxChars = DefaultMaxEvidenceChars
	}
	return Evidence{
		FindingID:    f.ID,
		Title:        f.Title,
		CheckName:    f.CheckName,
		RuleID:       f.RuleID,
		Target:       f.Target,
		Path:         f.Path,
		Severity:     string(f.Severity),
		Confidence:   string(f.Confidence),
		GateVerdict:  string(vf.Status),
		GateResults:  vf.GateResults,
		CWE:          ExtractCWE(f),
		Technology:   technology,
		AffectedPath: vf.AffectedPaths,
		Impact:       truncate(f.Impact, maxChars),
		Evidence:     truncate(validate.RedactEvidence(f.Evidence), maxChars),
		Request:      truncate(validate.RedactEvidence(f.Request), maxChars),
		Response:     truncate(validate.RedactEvidence(f.Response), maxChars),
		Remediation:  truncate(f.Remediation, 800),
	}
}

// HostKey reduces a target URL/host to a lowercase host without a port, so
// httpx technology fingerprints can be attached.
func HostKey(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	if idx := strings.LastIndex(target, ":"); idx != -1 && !strings.Contains(target[idx:], "]") {
		target = target[:idx]
	}
	return strings.ToLower(target)
}

// urlInText matches absolute URLs inside model prose.
var urlInText = regexp.MustCompile(`https?://[^\s"'<>\])]+`)

// EvidenceHosts collects every host a finding's evidence legitimately contains:
// the target plus any host appearing in the evidence, request, response, impact
// or remediation text.
func EvidenceHosts(f *findings.Finding) map[string]bool {
	hosts := map[string]bool{}
	if f == nil {
		return hosts
	}
	add := func(raw string) {
		if h := HostKey(raw); h != "" {
			hosts[h] = true
		}
	}
	add(f.Target)
	for _, text := range []string{f.Evidence, f.Request, f.Response, f.Impact, f.Remediation} {
		for _, u := range urlInText.FindAllString(text, -1) {
			add(u)
		}
	}
	return hosts
}

// GuardURLs replaces every URL whose host is not in allowed with replacement and
// reports whether anything changed. Model prose is advisory, but it is rendered
// next to the evidence a human approves, so ungrounded infrastructure must not
// survive.
func GuardURLs(text string, allowed map[string]bool, replacement string) (string, bool) {
	if text == "" || len(allowed) == 0 {
		return text, false
	}
	changed := false
	out := urlInText.ReplaceAllStringFunc(text, func(u string) string {
		if allowed[HostKey(u)] {
			return u
		}
		changed = true
		return replacement
	})
	return out, changed
}

// Run executes the batched triage. A nil Client means deterministic-only mode:
// every eligible finding becomes needs_human with an explicit reason.
func Run(ctx context.Context, list []*validate.ValidatedFinding, techByHost map[string][]string, opts Options) (*Report, error) {
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}
	if batchSize > MaxBatchSize {
		batchSize = MaxBatchSize
	}
	maxChars := opts.MaxEvidenceChars
	if maxChars <= 0 {
		maxChars = DefaultMaxEvidenceChars
	}
	logFn := opts.Log
	if logFn == nil {
		logFn = func(string, ...any) {}
	}

	report := &Report{
		Version:     Version,
		GeneratedAt: time.Now().UTC(),
		BatchSize:   batchSize,
		Counts:      map[string]int{},
	}
	if opts.Client != nil {
		report.Provider = opts.Client.Name()
		report.Model = opts.Model
	} else {
		report.Provider = "none"
		report.Model = "deterministic"
	}

	type item struct {
		evidence Evidence
		vf       *validate.ValidatedFinding
		firstCWE bool
	}

	var items []item
	seenCWE := make(map[string]bool)
	seenID := make(map[string]string)
	for _, vf := range list {
		if vf == nil || vf.Finding == nil {
			continue
		}
		// Suppressed findings are already final. The model cannot resurrect them
		// and never sees them.
		if vf.Status == validate.StatusSuppressed {
			report.ExcludedSuppressed++
			continue
		}
		// Finding IDs are the join key for triage, drafting and approval. A
		// duplicate ID across two targets would silently overwrite a verdict and
		// let an operator approve one host's draft while reading another's, so
		// it is reported instead of merged.
		if prevTarget, dup := seenID[vf.Finding.ID]; dup && prevTarget != vf.Finding.Target {
			report.LLMErrors = append(report.LLMErrors, truncate(fmt.Sprintf(
				"duplicate finding ID %q on %s and %s; keeping the first occurrence",
				vf.Finding.ID, prevTarget, vf.Finding.Target), 300))
			continue
		}
		seenID[vf.Finding.ID] = vf.Finding.Target

		cwe := ExtractCWE(vf.Finding)
		first := false
		if cwe != "" && !seenCWE[cwe] {
			seenCWE[cwe] = true
			first = true
		}

		ev := BuildEvidence(vf, techByHost[HostKey(vf.Finding.Target)], maxChars)
		ev.FirstCWE = first
		items = append(items, item{evidence: ev, vf: vf, firstCWE: first})
	}
	report.Eligible = len(items)
	if len(items) == 0 {
		return report, nil
	}

	verdicts := make(map[string]Verdict, len(items))
	for start := 0; start < len(items); start += batchSize {
		end := start + batchSize
		if end > len(items) {
			end = len(items)
		}
		chunk := items[start:end]

		evidences := make([]Evidence, 0, len(chunk))
		allowed := make(map[string]bool, len(chunk))
		for _, it := range chunk {
			evidences = append(evidences, it.evidence)
			allowed[it.evidence.FindingID] = true
		}

		var modelVerdicts []modelVerdict
		if opts.Client != nil {
			if err := ctx.Err(); err != nil {
				return report, err
			}
			mv, err := classifyBatch(ctx, opts.Client, evidences, allowed, logFn)
			if err != nil {
				report.LLMErrors = append(report.LLMErrors, truncate(err.Error(), 300))
				logFn("[WARN] triage batch %d failed, falling back to needs_human: %v", report.Batches+1, err)
			} else {
				modelVerdicts = mv
			}
		}
		report.Batches++

		byID := make(map[string]modelVerdict, len(modelVerdicts))
		for _, mv := range modelVerdicts {
			byID[mv.FindingID] = mv
		}

		for _, it := range chunk {
			v := Verdict{
				FindingID:      it.evidence.FindingID,
				Title:          it.evidence.Title,
				Target:         it.evidence.Target,
				Severity:       it.evidence.Severity,
				GateVerdict:    it.evidence.GateVerdict,
				Classification: NeedsHuman,
				Source:         "deterministic_fallback",
			}

			if mv, ok := byID[it.evidence.FindingID]; ok {
				v.Classification = Classification(mv.Classification)
				v.Rationale = mv.Rationale
				v.Confidence = mv.Confidence
				v.NextManualTest = mv.NextManualTest
				v.Source = "llm"
			} else if opts.Client != nil {
				v.Rationale = "No usable model verdict for this finding; deterministic fallback keeps it for human review."
			} else {
				v.Rationale = "LLM triage disabled; deterministic fallback keeps this finding for human review."
			}

			// The hard-rule layer runs on every verdict, whatever its source.
			ApplyHardRules(&v, RuleContext{
				GateStatus:         it.vf.Status,
				Severity:           it.vf.Finding.Severity,
				CWE:                it.evidence.CWE,
				FirstOccurrenceCWE: it.firstCWE,
			})

			// Model prose is shown to the reviewer right next to the evidence, so
			// ungrounded hosts are replaced here as well as in the draft guard.
			hosts := EvidenceHosts(it.vf.Finding)
			if guarded, changed := GuardURLs(v.Rationale, hosts, "[unverified URL removed]"); changed {
				v.Rationale = guarded
			}
			if guarded, changed := GuardURLs(v.NextManualTest, hosts, "[unverified URL removed]"); changed {
				v.NextManualTest = guarded
			}

			verdicts[v.FindingID] = v
		}
	}

	ordered := make([]Verdict, 0, len(items))
	for _, it := range items {
		ordered = append(ordered, verdicts[it.evidence.FindingID])
	}
	SortVerdicts(ordered)
	for i := range ordered {
		ordered[i].Rank = i + 1
		report.Counts[string(ordered[i].Classification)]++
	}
	report.Verdicts = ordered
	return report, nil
}

// classifyBatch performs one model call, retrying exactly once with a repair
// instruction if the response cannot be parsed. It never relaxes the schema.
func classifyBatch(ctx context.Context, client Client, batch []Evidence, allowed map[string]bool, logFn LogFunc) ([]modelVerdict, error) {
	userPrompt, err := buildUserPrompt(batch)
	if err != nil {
		return nil, err
	}

	resp, err := client.Complete(ctx, CompletionRequest{System: SystemPrompt, User: userPrompt})
	if err == nil {
		if parsed, parseErr := parseVerdicts(resp.Content, allowed); parseErr == nil {
			return parsed, nil
		} else {
			logFn("[INFO] triage response unusable (%v); retrying once", parseErr)
			err = parseErr
		}
	}

	retry, retryErr := client.Complete(ctx, CompletionRequest{System: SystemPrompt, User: repairPrompt(userPrompt)})
	if retryErr != nil {
		return nil, fmt.Errorf("%v; retry failed: %w", err, retryErr)
	}
	parsed, parseErr := parseVerdicts(retry.Content, allowed)
	if parseErr != nil {
		return nil, fmt.Errorf("%v; retry returned unparseable output: %w", err, parseErr)
	}
	return parsed, nil
}

// SortVerdicts orders verdicts for the report: strongest signal first, then
// severity, then confidence, then finding ID for determinism.
func SortVerdicts(list []Verdict) {
	classRank := map[Classification]int{LikelyTrue: 0, NeedsHuman: 1, LikelyFalse: 2}
	sevRank := map[string]int{
		string(findings.SeverityCritical): 0,
		string(findings.SeverityHigh):     1,
		string(findings.SeverityMedium):   2,
		string(findings.SeverityLow):      3,
		string(findings.SeverityInfo):     4,
	}

	sort.SliceStable(list, func(i, j int) bool {
		ci, cj := classRank[list[i].Classification], classRank[list[j].Classification]
		if ci != cj {
			return ci < cj
		}
		si, sj := sevRank[list[i].Severity], sevRank[list[j].Severity]
		if si != sj {
			return si < sj
		}
		if list[i].Confidence != list[j].Confidence {
			return list[i].Confidence > list[j].Confidence
		}
		return list[i].FindingID < list[j].FindingID
	})
}

// Lookup returns the verdict for a finding ID.
func (r *Report) Lookup(findingID string) (Verdict, bool) {
	for _, v := range r.Verdicts {
		if v.FindingID == findingID {
			return v, true
		}
	}
	return Verdict{}, false
}
