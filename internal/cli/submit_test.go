package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/draft"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

// submitFixture writes a run directory containing one validated finding, its
// triage verdict and its draft, so the approval gate has real inputs.
func submitFixture(t *testing.T, status validate.ValidationStatus, class triage.Classification) (*workspace.Workspace, *validate.ValidatedFinding, string) {
	t.Helper()

	ws, err := workspace.NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	f := findings.NewFinding("f-1", "header-hsts-missing", "https://example.com", "Missing HSTS header",
		findings.SeverityHigh, findings.ConfidenceHigh)
	f.RuleID = "missing-hsts-header"
	f.Path = "/login"
	f.Evidence = "strict-transport-security is absent"
	f.Request = "GET /login HTTP/1.1\nHost: example.com"
	f.Response = "HTTP/1.1 200 OK"
	vf := &validate.ValidatedFinding{
		Finding:       f,
		Status:        status,
		GateResults:   []validate.GateResult{{GateID: 1, Name: "Scope Verification", Passed: true}},
		AffectedPaths: []string{"/login"},
	}
	if err := ws.SaveValidatedFindings([]*validate.ValidatedFinding{vf}); err != nil {
		t.Fatalf("save validated findings: %v", err)
	}

	report := &triage.Report{
		Version:  triage.Version,
		Provider: "mock",
		Model:    "mock-model",
		Verdicts: []triage.Verdict{{
			FindingID:      f.ID,
			Rank:           1,
			Classification: class,
			Severity:       string(f.Severity),
			Confidence:     82,
			Rationale:      "The header is absent on the login page.",
			Source:         "llm",
			GateVerdict:    string(status),
		}},
	}
	if err := ws.SaveArtifact(workspace.TriageFile, report); err != nil {
		t.Fatalf("save triage: %v", err)
	}

	draftPath, err := ws.SaveDraft(draft.FileName(f.ID), "# draft\n\n- **Finding ID:** `"+f.ID+"`\n")
	if err != nil {
		t.Fatalf("save draft: %v", err)
	}
	return ws, vf, draftPath
}

// withSubmitFlags sets the package-level submit flags and restores them after.
func withSubmitFlags(t *testing.T, runDir, finding string, requireApproval bool, stdin string) {
	t.Helper()
	prevFrom, prevFinding, prevReq := submitFromRun, submitFinding, submitRequireApprov
	submitFromRun, submitFinding, submitRequireApprov = runDir, finding, requireApproval
	t.Cleanup(func() {
		submitFromRun, submitFinding, submitRequireApprov = prevFrom, prevFinding, prevReq
		submitCmd.SetIn(nil)
	})
	submitCmd.SetIn(strings.NewReader(stdin))
}

func queuePath(ws *workspace.Workspace) string {
	return ws.Dir + string(os.PathSeparator) + workspace.SubmissionQueueFile
}

// There is no approval path without --require-approval.
func TestSubmitRefusesWithoutRequireApproval(t *testing.T) {
	ws, _, _ := submitFixture(t, validate.StatusVerified, triage.LikelyTrue)
	withSubmitFlags(t, ws.Dir, "f-1", false, "APPROVE\n")

	err := runSubmit(submitCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--require-approval is mandatory") {
		t.Fatalf("expected refusal without --require-approval, got %v", err)
	}
	if _, statErr := os.Stat(queuePath(ws)); !os.IsNotExist(statErr) {
		t.Fatal("submission queue must not be created without explicit approval")
	}
}

// Typing APPROVE marks the finding submission_ready in the workspace.
func TestSubmitApproveWritesQueueEntry(t *testing.T) {
	ws, vf, _ := submitFixture(t, validate.StatusVerified, triage.LikelyTrue)
	withSubmitFlags(t, ws.Dir, "f-1", true, "APPROVE\n")

	if err := runSubmit(submitCmd, nil); err != nil {
		t.Fatalf("runSubmit: %v", err)
	}

	var queue submissionQueue
	if err := ws.LoadArtifact(workspace.SubmissionQueueFile, &queue); err != nil {
		t.Fatalf("load submission queue: %v", err)
	}
	if len(queue.Entries) != 1 {
		t.Fatalf("expected 1 queue entry, got %d", len(queue.Entries))
	}
	entry := queue.Entries[0]
	if entry.FindingID != vf.Finding.ID {
		t.Errorf("finding id = %q, want %q", entry.FindingID, vf.Finding.ID)
	}
	if entry.GateVerdict != string(validate.StatusVerified) {
		t.Errorf("gate verdict = %q, want Verified", entry.GateVerdict)
	}
	if entry.SubmissionChannel != submissionChannelManual {
		t.Errorf("submission channel = %q, want the manual marker", entry.SubmissionChannel)
	}
	if entry.DraftFile != draft.FileName(vf.Finding.ID) {
		t.Errorf("draft file = %q", entry.DraftFile)
	}
}

// Anything other than APPROVE cancels without writing.
func TestSubmitNonApprovalWritesNothing(t *testing.T) {
	ws, _, _ := submitFixture(t, validate.StatusVerified, triage.LikelyTrue)
	withSubmitFlags(t, ws.Dir, "f-1", true, "approve\n")

	if err := runSubmit(submitCmd, nil); err != nil {
		t.Fatalf("runSubmit: %v", err)
	}
	if _, err := os.Stat(queuePath(ws)); !os.IsNotExist(err) {
		t.Fatal("queue must not be written when the operator does not type APPROVE")
	}
}

// The draft must exist before approval; the gate does not approve ideas.
func TestSubmitRequiresExistingDraft(t *testing.T) {
	ws, _, draftPath := submitFixture(t, validate.StatusVerified, triage.LikelyTrue)
	if err := os.Remove(draftPath); err != nil {
		t.Fatalf("remove draft: %v", err)
	}
	withSubmitFlags(t, ws.Dir, "f-1", true, "APPROVE\n")

	err := runSubmit(submitCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "report --draft") {
		t.Fatalf("expected a missing-draft error, got %v", err)
	}
	if _, statErr := os.Stat(queuePath(ws)); !os.IsNotExist(statErr) {
		t.Fatal("queue must not be written when the draft is missing")
	}
}

// Suppressed findings never enter the approval queue, and NeedsManualReview
// findings do (the operator's keystroke is their only verification).
func TestApprovalCandidatesRespectGateVerdicts(t *testing.T) {
	verified := &validate.ValidatedFinding{
		Finding: findings.NewFinding("v", "c", "https://example.com", "verified", findings.SeverityHigh, findings.ConfidenceHigh),
		Status:  validate.StatusVerified,
	}
	manual := &validate.ValidatedFinding{
		Finding: findings.NewFinding("m", "c", "https://example.com", "manual", findings.SeverityMedium, findings.ConfidenceMedium),
		Status:  validate.StatusNeedsManualReview,
	}
	suppressed := &validate.ValidatedFinding{
		Finding: findings.NewFinding("s", "c", "https://example.com", "suppressed", findings.SeverityLow, findings.ConfidenceLow),
		Status:  validate.StatusSuppressed,
	}
	byID := map[string]*validate.ValidatedFinding{"v": verified, "m": manual, "s": suppressed}

	report := triage.Report{Verdicts: []triage.Verdict{
		{FindingID: "v", Rank: 1, Classification: triage.LikelyTrue},
		{FindingID: "m", Rank: 2, Classification: triage.NeedsHuman},
		{FindingID: "s", Rank: 3, Classification: triage.LikelyTrue},
	}}

	got := approvalCandidates(report, byID, submissionQueue{})
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(got))
	}
	for _, c := range got {
		if c.finding.Finding.ID == "s" {
			t.Fatal("suppressed finding must never be an approval candidate")
		}
	}
	if got[0].finding.Finding.ID != "v" || got[1].finding.Finding.ID != "m" {
		t.Errorf("candidates not rank-ordered: %s, %s", got[0].finding.Finding.ID, got[1].finding.Finding.ID)
	}
}

// With several pending candidates the operator must name one explicitly.
func TestSelectCandidateRequiresExplicitIDWhenAmbiguous(t *testing.T) {
	a := &validate.ValidatedFinding{Finding: findings.NewFinding("a", "c", "https://a.example", "a", findings.SeverityHigh, findings.ConfidenceHigh)}
	b := &validate.ValidatedFinding{Finding: findings.NewFinding("b", "c", "https://b.example", "b", findings.SeverityLow, findings.ConfidenceLow)}
	candidates := []approvalCandidate{
		{rank: 1, finding: a, verdict: triage.Verdict{FindingID: "a"}},
		{rank: 2, finding: b, verdict: triage.Verdict{FindingID: "b"}},
	}

	if _, err := selectCandidate(candidates, "", "run"); err == nil || !strings.Contains(err.Error(), "--finding") {
		t.Fatalf("expected an ambiguity error, got %v", err)
	}
	got, err := selectCandidate(candidates, "b", "run")
	if err != nil {
		t.Fatalf("selectCandidate(b): %v", err)
	}
	if got.finding.Finding.ID != "b" {
		t.Errorf("selected %q, want b", got.finding.Finding.ID)
	}
	if _, err := selectCandidate(candidates, "missing", "run"); err == nil {
		t.Fatal("expected an error for an unknown finding ID")
	}
}

// Already-approved findings are not offered again.
func TestSelectCandidateSkipsApproved(t *testing.T) {
	a := &validate.ValidatedFinding{Finding: findings.NewFinding("a", "c", "https://a.example", "a", findings.SeverityHigh, findings.ConfidenceHigh)}
	b := &validate.ValidatedFinding{Finding: findings.NewFinding("b", "c", "https://b.example", "b", findings.SeverityLow, findings.ConfidenceLow)}
	candidates := []approvalCandidate{
		{rank: 1, finding: a, verdict: triage.Verdict{FindingID: "a"}, approved: true},
		{rank: 2, finding: b, verdict: triage.Verdict{FindingID: "b"}},
	}

	got, err := selectCandidate(candidates, "", "run")
	if err != nil {
		t.Fatalf("selectCandidate: %v", err)
	}
	if got.finding.Finding.ID != "b" {
		t.Errorf("selected %q, want the single pending finding b", got.finding.Finding.ID)
	}

	all := []approvalCandidate{{rank: 1, finding: a, approved: true}}
	if _, err := selectCandidate(all, "", "run"); err == nil {
		t.Fatal("expected 'nothing to approve' when every candidate is approved")
	}
}

// The confirmation prompt is exact-match and newline tolerant.
func TestPromptApproval(t *testing.T) {
	cases := map[string]bool{
		"APPROVE\n":     true,
		"  APPROVE  \n": true,
		"APPROVE":       true,
		"APPROVE ALL\n": false,
		"yes\n":         false,
		"":              false,
	}
	for input, want := range cases {
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader(input))
		got, err := promptApproval(cmd)
		if err != nil {
			t.Fatalf("promptApproval(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("promptApproval(%q) = %v, want %v", input, got, want)
		}
	}
}
