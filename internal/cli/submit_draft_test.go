package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/draft"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
)

// A draft that does not belong to the finding must not be approvable.
func TestSubmitRejectsMismatchedDraft(t *testing.T) {
	ws, vf, draftPath := submitFixture(t, validate.StatusVerified, triage.LikelyTrue)

	// Overwrite the draft with one that mentions a different finding.
	stale := "# stale draft\n\n- **Finding ID:** `some-other-finding`\n"
	if err := os.WriteFile(draftPath, []byte(stale), 0644); err != nil {
		t.Fatalf("overwrite draft: %v", err)
	}

	withSubmitFlags(t, ws.Dir, vf.Finding.ID, true, "APPROVE\n")
	err := runSubmit(submitCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "does not belong to finding") {
		t.Fatalf("expected a draft-mismatch error, got %v", err)
	}
	if _, statErr := os.Stat(queuePath(ws)); !os.IsNotExist(statErr) {
		t.Fatal("queue must not be written for a mismatched draft")
	}
}

// A draft for f-10 must not approve f-1: matching a bare ID substring would
// let a sibling finding's draft pass the identity check.
func TestSubmitRejectsPrefixSiblingDraft(t *testing.T) {
	ws, vf, draftPath := submitFixture(t, validate.StatusVerified, triage.LikelyTrue)

	sibling := "# sibling draft\n\n- **Finding ID:** `" + vf.Finding.ID + "0`\n"
	if err := os.WriteFile(draftPath, []byte(sibling), 0644); err != nil {
		t.Fatalf("overwrite draft: %v", err)
	}

	withSubmitFlags(t, ws.Dir, vf.Finding.ID, true, "APPROVE\n")
	err := runSubmit(submitCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "does not belong to finding") {
		t.Fatalf("expected a draft-mismatch error for a prefix sibling, got %v", err)
	}
	if _, statErr := os.Stat(queuePath(ws)); !os.IsNotExist(statErr) {
		t.Fatal("queue must not be written for a mismatched draft")
	}
}

// The draft path used for approval must be the same sanitised name the drafter
// produced, so a finding ID cannot be used to reach another file.
func TestDraftFileNameForMatchesDrafter(t *testing.T) {
	for _, id := range []string{"nuclei-abc123", "CVE-2024-1234", "../../etc/passwd", ""} {
		vf := &validate.ValidatedFinding{
			Finding: findings.NewFinding(id, "c", "https://example.com", "t", findings.SeverityLow, findings.ConfidenceLow),
		}
		if got, want := draftFileNameFor(vf), draft.FileName(id); got != want {
			t.Errorf("draftFileNameFor(%q) = %q, draft.FileName = %q", id, got, want)
		}
	}
}
