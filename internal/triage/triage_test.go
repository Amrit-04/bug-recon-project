package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

func makeValidated(id, severity string, status validate.ValidationStatus, impact string) *validate.ValidatedFinding {
	f := findings.NewFinding(id, "test", "api.example.com", "Title "+id, findings.Severity(severity), findings.ConfidenceHigh)
	f.Impact = impact
	f.Evidence = "matched evidence for " + id
	return &validate.ValidatedFinding{Finding: f, Status: status}
}

// promptEvidences extracts the evidence array from a user prompt produced by
// buildUserPrompt.
func promptEvidences(t *testing.T, prompt string) []Evidence {
	t.Helper()
	idx := strings.Index(prompt, "FINDINGS:\n")
	if idx == -1 {
		t.Fatalf("prompt missing FINDINGS section: %s", prompt)
	}
	payload := prompt[idx+len("FINDINGS:\n"):]
	// Drop any appended repair instruction.
	if cut := strings.Index(payload, "\n\nYour previous reply"); cut != -1 {
		payload = payload[:cut]
	}
	var batch []Evidence
	if err := json.Unmarshal([]byte(payload), &batch); err != nil {
		t.Fatalf("decode prompt evidence: %v", err)
	}
	return batch
}

func TestParseVerdicts(t *testing.T) {
	allowed := map[string]bool{"A": true, "B": true}

	content := "```json\n" + `{"findings":[
		{"finding_id":"A","classification":"Likely True","rationale":"git HEAD matched","confidence":180,"next_manual_test":"curl /.git/HEAD"},
		{"finding_id":"B","classification":"maybe","rationale":"","confidence":50},
		{"finding_id":"C","classification":"likely_false","rationale":"injected","confidence":10}
	]}` + "\n```"

	got, err := parseVerdicts(content, allowed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 usable verdict, got %d: %+v", len(got), got)
	}
	if got[0].FindingID != "A" || got[0].Classification != string(LikelyTrue) {
		t.Errorf("unexpected verdict: %+v", got[0])
	}
	if got[0].Confidence != 100 {
		t.Errorf("confidence must be clamped to 100, got %d", got[0].Confidence)
	}
	if got[0].NextManualTest == "" {
		t.Error("expected next_manual_test preserved")
	}
}

func TestParseVerdictsRejectsGarbage(t *testing.T) {
	if _, err := parseVerdicts("I think finding A is probably real.", map[string]bool{"A": true}); err == nil {
		t.Fatal("expected an error for free-text output")
	}
	if _, err := parseVerdicts(`{"verdicts":[]}`, map[string]bool{"A": true}); err == nil {
		t.Fatal("expected an error when findings array is missing")
	}
}

func TestApplyHardRules(t *testing.T) {
	cases := []struct {
		name       string
		verdict    Verdict
		ctx        RuleContext
		want       Classification
		wantRules  int
		wantSource string
	}{
		{
			name:       "verified veto",
			verdict:    Verdict{Classification: LikelyFalse, Confidence: 10, Source: "llm"},
			ctx:        RuleContext{GateStatus: validate.StatusVerified, Severity: findings.SeverityLow},
			want:       NeedsHuman,
			wantRules:  1,
			wantSource: "llm+hard_rule",
		},
		{
			name:       "high severity veto",
			verdict:    Verdict{Classification: LikelyFalse, Confidence: 80, Source: "llm"},
			ctx:        RuleContext{GateStatus: validate.StatusNeedsManualReview, Severity: findings.SeverityHigh},
			want:       NeedsHuman,
			wantRules:  1,
			wantSource: "llm+hard_rule",
		},
		{
			name:       "critical severity veto",
			verdict:    Verdict{Classification: LikelyFalse, Confidence: 80, Source: "llm"},
			ctx:        RuleContext{GateStatus: validate.StatusNeedsManualReview, Severity: findings.SeverityCritical},
			want:       NeedsHuman,
			wantRules:  1,
			wantSource: "llm+hard_rule",
		},
		{
			name:       "first cwe veto",
			verdict:    Verdict{Classification: LikelyFalse, Confidence: 80, Source: "llm"},
			ctx:        RuleContext{GateStatus: validate.StatusNeedsManualReview, Severity: findings.SeverityMedium, CWE: "CWE-79", FirstOccurrenceCWE: true},
			want:       NeedsHuman,
			wantRules:  1,
			wantSource: "llm+hard_rule",
		},
		{
			name:       "no rule applies",
			verdict:    Verdict{Classification: LikelyFalse, Confidence: 80, Source: "llm"},
			ctx:        RuleContext{GateStatus: validate.StatusNeedsManualReview, Severity: findings.SeverityMedium, CWE: "CWE-79", FirstOccurrenceCWE: false},
			want:       LikelyFalse,
			wantRules:  0,
			wantSource: "llm",
		},
		{
			name:       "never promotes",
			verdict:    Verdict{Classification: LikelyTrue, Confidence: 90, Source: "llm"},
			ctx:        RuleContext{GateStatus: validate.StatusVerified, Severity: findings.SeverityCritical, CWE: "CWE-79", FirstOccurrenceCWE: true},
			want:       LikelyTrue,
			wantRules:  0,
			wantSource: "llm",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.verdict
			ApplyHardRules(&v, tc.ctx)
			if v.Classification != tc.want {
				t.Errorf("classification = %q, want %q", v.Classification, tc.want)
			}
			if len(v.HardRuleOverrides) != tc.wantRules {
				t.Errorf("rule overrides = %v, want %d rules", v.HardRuleOverrides, tc.wantRules)
			}
			if v.Source != tc.wantSource {
				t.Errorf("source = %q, want %q", v.Source, tc.wantSource)
			}
			if tc.want == NeedsHuman && len(v.HardRuleOverrides) > 0 && v.Confidence < minOverrideConfidence {
				t.Errorf("confidence should be floored at %d, got %d", minOverrideConfidence, v.Confidence)
			}
		})
	}
}

func TestRunBatchesAndAppliesHardRules(t *testing.T) {
	var list []*validate.ValidatedFinding
	for i := 0; i < 25; i++ {
		list = append(list, makeValidated(fmt.Sprintf("F-%02d", i), string(findings.SeverityMedium),
			validate.StatusNeedsManualReview, ""))
	}

	batchSizes := []int{}
	client := &MockClient{Provider: "mock", Func: func(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
		evs := promptEvidences(t, req.User)
		batchSizes = append(batchSizes, len(evs))
		var verdicts []string
		for _, e := range evs {
			// Every model verdict claims likely_false; hard rules must veto
			// nothing here because severity is medium and no CWE is present.
			verdicts = append(verdicts, fmt.Sprintf(
				`{"finding_id":%q,"classification":"likely_false","rationale":"no impact visible","confidence":70}`, e.FindingID))
		}
		return CompletionResponse{Content: `{"findings":[` + strings.Join(verdicts, ",") + `]}`}, nil
	}}

	report, err := Run(context.Background(), list, nil, Options{Client: client, Model: "test-model", BatchSize: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Batches != 3 {
		t.Errorf("expected 3 batches for 25 findings at size 10, got %d", report.Batches)
	}
	want := []int{10, 10, 5}
	if len(batchSizes) != len(want) {
		t.Fatalf("expected %d model calls, got %v", len(want), batchSizes)
	}
	for i := range want {
		if batchSizes[i] != want[i] {
			t.Errorf("batch %d size = %d, want %d", i, batchSizes[i], want[i])
		}
	}

	if report.Counts[string(LikelyFalse)] != 25 {
		t.Errorf("expected 25 likely_false verdicts, got %+v", report.Counts)
	}
	if report.Provider != "mock" || report.Model != "test-model" {
		t.Errorf("unexpected provider/model: %s/%s", report.Provider, report.Model)
	}
	if report.Verdicts[0].Rank != 1 {
		t.Errorf("expected ranks to start at 1, got %d", report.Verdicts[0].Rank)
	}
}

func TestRunVerifiedAndHighSeveritySurviveLikelyFalse(t *testing.T) {
	list := []*validate.ValidatedFinding{
		makeValidated("V-1", string(findings.SeverityHigh), validate.StatusVerified, "CWE-538: Insertion of Sensitive Information"),
		makeValidated("V-2", string(findings.SeverityLow), validate.StatusNeedsManualReview, ""),
	}

	client := &MockClient{Func: func(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
		evs := promptEvidences(t, req.User)
		var verdicts []string
		for _, e := range evs {
			verdicts = append(verdicts, fmt.Sprintf(
				`{"finding_id":%q,"classification":"likely_false","rationale":"looks like a soft 404","confidence":88}`, e.FindingID))
		}
		return CompletionResponse{Content: `{"findings":[` + strings.Join(verdicts, ",") + `]}`}, nil
	}}

	report, err := Run(context.Background(), list, nil, Options{Client: client, BatchSize: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	first, ok := report.Lookup("V-1")
	if !ok {
		t.Fatal("missing verdict for V-1")
	}
	if first.Classification != NeedsHuman {
		t.Errorf("verified high-severity finding must not stay likely_false, got %q", first.Classification)
	}
	if len(first.HardRuleOverrides) != 3 {
		t.Errorf("expected all three overrides, got %v", first.HardRuleOverrides)
	}

	second, _ := report.Lookup("V-2")
	if second.Classification != LikelyFalse {
		t.Errorf("low severity, unverified finding may keep likely_false, got %q", second.Classification)
	}
}

func TestRunExcludesSuppressedFindings(t *testing.T) {
	list := []*validate.ValidatedFinding{
		makeValidated("S-1", string(findings.SeverityLow), validate.StatusSuppressed, ""),
		makeValidated("S-2", string(findings.SeverityLow), validate.StatusNeedsManualReview, ""),
	}

	sentIDs := map[string]bool{}
	client := &MockClient{Func: func(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
		for _, e := range promptEvidences(t, req.User) {
			sentIDs[e.FindingID] = true
		}
		return CompletionResponse{Content: `{"findings":[{"finding_id":"S-2","classification":"needs_human","rationale":"manual check","confidence":40}]}`}, nil
	}}

	report, err := Run(context.Background(), list, nil, Options{Client: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sentIDs["S-1"] {
		t.Error("suppressed findings must never be sent to the model")
	}
	if report.ExcludedSuppressed != 1 {
		t.Errorf("expected 1 excluded suppressed finding, got %d", report.ExcludedSuppressed)
	}
	if len(report.Verdicts) != 1 {
		t.Errorf("expected 1 verdict, got %d", len(report.Verdicts))
	}
}

func TestRunWithoutLLMDegradesToNeedsHuman(t *testing.T) {
	list := []*validate.ValidatedFinding{
		makeValidated("D-1", string(findings.SeverityLow), validate.StatusNeedsManualReview, ""),
		makeValidated("D-2", string(findings.SeverityHigh), validate.StatusVerified, "CWE-200: Exposure"),
	}

	report, err := Run(context.Background(), list, nil, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Counts[string(NeedsHuman)] != 2 {
		t.Errorf("deterministic mode must yield needs_human only, got %+v", report.Counts)
	}
	if report.Counts[string(LikelyFalse)] != 0 {
		t.Error("deterministic mode must never suppress findings")
	}
	if report.Provider != "none" {
		t.Errorf("expected provider none, got %q", report.Provider)
	}
	for _, v := range report.Verdicts {
		if v.Source != "deterministic_fallback" {
			t.Errorf("unexpected source %q", v.Source)
		}
	}
}

func TestRunModelFailureFallsBack(t *testing.T) {
	list := []*validate.ValidatedFinding{
		makeValidated("E-1", string(findings.SeverityMedium), validate.StatusNeedsManualReview, ""),
	}
	client := &MockClient{Func: func(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
		return CompletionResponse{}, fmt.Errorf("connection refused")
	}}

	report, err := Run(context.Background(), list, nil, Options{Client: client})
	if err != nil {
		t.Fatalf("LLM failure must not fail the run: %v", err)
	}
	if len(report.LLMErrors) == 0 {
		t.Error("expected the LLM error to be recorded")
	}
	if report.Verdicts[0].Classification != NeedsHuman {
		t.Errorf("expected needs_human fallback, got %q", report.Verdicts[0].Classification)
	}
}

func TestRunModelOutputMustBeJSON(t *testing.T) {
	list := []*validate.ValidatedFinding{
		makeValidated("J-1", string(findings.SeverityLow), validate.StatusNeedsManualReview, ""),
	}
	client := &MockClient{Func: func(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
		return CompletionResponse{Content: "Finding J-1 looks real to me."}, nil
	}}

	report, err := Run(context.Background(), list, nil, Options{Client: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verdicts[0].Classification != NeedsHuman {
		t.Errorf("free-text output must not be trusted, got %q", report.Verdicts[0].Classification)
	}
	if len(report.LLMErrors) == 0 {
		t.Error("expected parse errors to be recorded")
	}
}

func TestBuildEvidenceRedactsSecrets(t *testing.T) {
	f := findings.NewFinding("R-1", "exposure", "https://api.example.com/.env", "Exposed .env", findings.SeverityHigh, findings.ConfidenceHigh)
	f.Evidence = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	f.Request = "GET /.env HTTP/1.1\r\nAuthorization: Bearer abcdef123456\r\n"
	f.Impact = "CWE-200: Exposure of Sensitive Information"

	vf := &validate.ValidatedFinding{Finding: f, Status: validate.StatusVerified, GateResults: []validate.GateResult{{GateID: 1, Name: "Scope Verification", Passed: true}}}

	ev := BuildEvidence(vf, []string{"nginx"}, 1000)
	if strings.Contains(ev.Evidence, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key must be redacted before reaching the model")
	}
	if strings.Contains(ev.Request, "abcdef123456") {
		t.Error("bearer token must be redacted before reaching the model")
	}
	if ev.CWE != "CWE-200" {
		t.Errorf("expected CWE-200, got %q", ev.CWE)
	}
	if ev.GateVerdict != string(validate.StatusVerified) {
		t.Errorf("expected gate verdict preserved, got %q", ev.GateVerdict)
	}
	if len(ev.Technology) != 1 || ev.Technology[0] != "nginx" {
		t.Errorf("expected technology attached, got %v", ev.Technology)
	}
}

func TestHostKey(t *testing.T) {
	cases := map[string]string{
		"https://API.Example.com:8443/path?x=1": "api.example.com",
		"api.example.com:443":                   "api.example.com",
		"api.example.com":                       "api.example.com",
		"":                                      "",
	}
	for in, want := range cases {
		if got := HostKey(in); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortVerdictsDeterministic(t *testing.T) {
	list := []Verdict{
		{FindingID: "c", Classification: LikelyFalse, Severity: string(findings.SeverityHigh), Confidence: 90},
		{FindingID: "b", Classification: LikelyTrue, Severity: string(findings.SeverityLow), Confidence: 60},
		{FindingID: "a", Classification: LikelyTrue, Severity: string(findings.SeverityCritical), Confidence: 40},
		{FindingID: "d", Classification: NeedsHuman, Severity: string(findings.SeverityCritical), Confidence: 95},
	}
	SortVerdicts(list)

	gotOrder := []string{list[0].FindingID, list[1].FindingID, list[2].FindingID, list[3].FindingID}
	wantOrder := []string{"a", "b", "d", "c"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("order = %v, want %v", gotOrder, wantOrder)
		}
	}
}

// The same ID on two different targets cannot be joined by any downstream
// artifact, so only the first occurrence is triaged.
func TestRunRejectsDuplicateIDsAcrossTargets(t *testing.T) {
	first := makeValidated("DUP-1", string(findings.SeverityLow), validate.StatusNeedsManualReview, "")
	second := makeValidated("DUP-1", string(findings.SeverityLow), validate.StatusNeedsManualReview, "")
	second.Finding.Target = "https://other.example.com"

	report, err := Run(context.Background(), []*validate.ValidatedFinding{first, second}, nil, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Verdicts) != 1 {
		t.Fatalf("expected 1 verdict for a duplicate ID, got %d", len(report.Verdicts))
	}
	if len(report.LLMErrors) == 0 {
		t.Error("expected the duplicate to be recorded as an error")
	}
}

// Model prose is advisory, but it is rendered next to evidence a human
// approves, so an unverified host must not survive in a rationale.
func TestRunGuardsModelURLsInProse(t *testing.T) {
	list := []*validate.ValidatedFinding{
		makeValidated("U-1", string(findings.SeverityMedium), validate.StatusNeedsManualReview, ""),
	}
	client := &MockClient{Func: func(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
		return CompletionResponse{Content: `{"findings":[
			{"finding_id":"U-1","classification":"needs_human","rationale":"See https://attacker.invalid/poc for the exploit","confidence":50,"next_manual_test":"curl https://attacker.invalid/verify"}
		]}`}, nil
	}}

	report, err := Run(context.Background(), list, nil, Options{Client: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v := report.Verdicts[0]
	if strings.Contains(v.Rationale, "attacker.invalid") || strings.Contains(v.NextManualTest, "attacker.invalid") {
		t.Fatalf("model prose kept an unverified URL: %+v", v)
	}
}
