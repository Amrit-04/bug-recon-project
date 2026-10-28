package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/draft"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

// submissionQueue is the workspace artifact that records findings a human has
// explicitly approved. It is a local queue only: scoutr never contacts a bug
// bounty platform, so "submission_ready" means "a human said yes, go submit it
// yourself".
type submissionQueue struct {
	Version   string            `json:"version"`
	UpdatedAt time.Time         `json:"updated_at"`
	Entries   []submissionEntry `json:"entries"`
}

type submissionEntry struct {
	FindingID            string    `json:"finding_id"`
	Title                string    `json:"title"`
	Severity             string    `json:"severity"`
	GateVerdict          string    `json:"gate_verdict"`
	TriageClassification string    `json:"triage_classification"`
	TriageConfidence     int       `json:"triage_confidence"`
	TriageRationale      string    `json:"triage_rationale,omitempty"`
	DraftFile            string    `json:"draft_file"`
	ApprovedAt           time.Time `json:"approved_at"`
	ApprovedBy           string    `json:"approved_by,omitempty"`
	SubmissionChannel    string    `json:"submission_channel"`
}

const submissionChannelManual = "manual (scoutr never calls a platform API)"

var (
	submitFromRun       string
	submitFinding       string
	submitRequireApprov bool
	submitList          bool
)

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Human approval gate: queue a human-approved draft as submission_ready (Tier 3)",
	Long: `Tier 3 gate. Nothing here is automatic.

This command:
  - reads the draft produced by "scoutr report --draft"
  - prints the finding title, severity, triage classification and rationale, and
    the exact evidence bundle from validated_findings.json
  - requires you to type APPROVE at the prompt
  - then appends the finding to submission_ready.json in the workspace

This command never:
  - calls a bug bounty platform API (there is no network client in this path)
  - approves anything without an interactive keystroke, so --require-approval
    is mandatory and cannot be defaulted on
  - accepts a suppressed finding, or a finding the gate did not produce

Both Verified and NeedsManualReview findings from the 7-Check gate pass through
this same gate. Uploading the draft afterwards is your action, not scoutr's.
`,
	Example: `  scoutr submit --require-approval --from .scoutr/runs/example.com-20261028-101500 --finding nuclei-1a2b3c
  scoutr submit --list --from .scoutr/runs/example.com-20261028-101500`,
	RunE: runSubmit,
}

func init() {
	submitCmd.Flags().StringVar(&submitFromRun, "from", "", "Workspace run directory containing validated_findings.json, triage.json and reports/drafts")
	submitCmd.Flags().StringVar(&submitFinding, "finding", "", "Finding ID to approve (defaults to the only remaining candidate)")
	submitCmd.Flags().BoolVar(&submitRequireApprov, "require-approval", false, "Mandatory: interactive APPROVE confirmation before a finding is marked submission_ready")
	submitCmd.Flags().BoolVar(&submitList, "list", false, "List the approval queue and the findings already marked submission_ready")
	RootCmd.AddCommand(submitCmd)
}

func runSubmit(cmd *cobra.Command, args []string) error {
	if submitFromRun == "" {
		return fmt.Errorf("--from <run-dir> is required")
	}
	ws, err := workspace.OpenRun(submitFromRun)
	if err != nil {
		return fmt.Errorf("open workspace: %w", err)
	}

	queue, err := loadSubmissionQueue(ws)
	if err != nil {
		return err
	}

	validated, err := ws.LoadValidatedFindings()
	if err != nil {
		return fmt.Errorf("load validated findings: %w", err)
	}
	byID := make(map[string]*validate.ValidatedFinding, len(validated))
	for _, vf := range validated {
		if vf == nil || vf.Finding == nil || vf.Status == validate.StatusSuppressed {
			continue
		}
		byID[vf.Finding.ID] = vf
	}

	var triageReport triage.Report
	if err := ws.LoadArtifact(workspace.TriageFile, &triageReport); err != nil {
		return fmt.Errorf("load %s: %w (run `scoutr triage --from %s` first)", workspace.TriageFile, err, submitFromRun)
	}

	candidates := approvalCandidates(triageReport, byID, queue)

	if submitList {
		printApprovalQueue(candidates, queue)
		return nil
	}

	// No approval path exists without this flag; the flag itself is not enough
	// either, because the APPROVE prompt below is unconditional.
	if !submitRequireApprov {
		return fmt.Errorf("refusing to run: --require-approval is mandatory (there is no auto-approval path)")
	}

	target, err := selectCandidate(candidates, submitFinding, submitFromRun)
	if err != nil {
		return err
	}
	verdict := target.verdict
	vf := target.finding
	f := vf.Finding

	// The draft must exist and must be the draft for this finding: a human is
	// approving a document, not an idea.
	draftName := draftFileNameFor(vf)
	draftPath, err := ws.DraftPath(draftName)
	if err != nil {
		return err
	}
	draftBody, err := os.ReadFile(draftPath)
	if err != nil {
		return fmt.Errorf("draft %s is not readable: %w (run `scoutr report --draft --from %s` first)", draftPath, err, submitFromRun)
	}
	if len(strings.TrimSpace(string(draftBody))) == 0 {
		return fmt.Errorf("draft %s is empty; re-run `scoutr report --draft --from %s`", draftPath, submitFromRun)
	}
	if !strings.Contains(string(draftBody), draftIdentity(f.ID)) {
		return fmt.Errorf("draft %s does not belong to finding %s; re-run `scoutr report --draft --from %s`", draftPath, f.ID, submitFromRun)
	}

	printApprovalSummary(f, vf, verdict, draftPath, len(draftBody))

	approved, err := promptApproval(cmd)
	if err != nil {
		return err
	}
	if !approved {
		fmt.Println("\nNot approved. Nothing was written and nothing was sent.")
		return nil
	}

	entry := submissionEntry{
		FindingID:            f.ID,
		Title:                f.Title,
		Severity:             string(f.Severity),
		GateVerdict:          string(vf.Status),
		TriageClassification: string(verdict.Classification),
		TriageConfidence:     verdict.Confidence,
		TriageRationale:      verdict.Rationale,
		DraftFile:            draftName,
		ApprovedAt:           time.Now().UTC(),
		ApprovedBy:           sysUser(),
		SubmissionChannel:    submissionChannelManual,
	}
	if err := saveSubmissionEntry(ws, &queue, entry); err != nil {
		return err
	}

	fmt.Printf("\nMarked %s as submission_ready in %s/%s\n", f.ID, ws.Dir, workspace.SubmissionQueueFile)
	fmt.Println("No network request was made. scoutr does not submit to any platform; upload the draft yourself.")
	return nil
}

// approvalCandidate is one gate-eligible finding with its triage verdict.
type approvalCandidate struct {
	rank     int
	finding  *validate.ValidatedFinding
	verdict  triage.Verdict
	approved bool
}

// approvalCandidates joins triage verdicts to gate verdicts. Only findings that
// the 7-Check gate either Verified or flagged for manual review can ever enter
// the approval queue; suppressed findings are structurally excluded.
func approvalCandidates(report triage.Report, byID map[string]*validate.ValidatedFinding, queue submissionQueue) []approvalCandidate {
	approvedIDs := make(map[string]bool, len(queue.Entries))
	for _, e := range queue.Entries {
		approvedIDs[e.FindingID] = true
	}

	var out []approvalCandidate
	for _, v := range report.Verdicts {
		vf, ok := byID[v.FindingID]
		if !ok {
			continue
		}
		if vf.Status != validate.StatusVerified && vf.Status != validate.StatusNeedsManualReview {
			continue
		}
		out = append(out, approvalCandidate{
			rank:     v.Rank,
			finding:  vf,
			verdict:  v,
			approved: approvedIDs[v.FindingID],
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].rank < out[j].rank })
	return out
}

// selectCandidate resolves --finding, or falls back to the only unapproved
// candidate so the operator never has to guess an ID.
func selectCandidate(candidates []approvalCandidate, findingID, runDir string) (approvalCandidate, error) {
	if findingID != "" {
		for _, c := range candidates {
			if c.finding.Finding.ID == findingID {
				return c, nil
			}
		}
		return approvalCandidate{}, fmt.Errorf("finding %q is not in the approval queue for %s (run `scoutr submit --list --from %s`)", findingID, runDir, runDir)
	}

	var open []approvalCandidate
	for _, c := range candidates {
		if !c.approved {
			open = append(open, c)
		}
	}
	switch len(open) {
	case 0:
		return approvalCandidate{}, fmt.Errorf("nothing to approve: every candidate is already submission_ready")
	case 1:
		return open[0], nil
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "%d candidates are waiting for approval; pass --finding <id>:\n", len(open))
		for _, c := range open {
			fmt.Fprintf(&b, "  %-40s [%s] %s %s\n", c.finding.Finding.ID, c.verdict.Classification,
				strings.ToUpper(string(c.finding.Finding.Severity)), c.finding.Finding.Title)
		}
		return approvalCandidate{}, fmt.Errorf("%s", b.String())
	}
}

func printApprovalQueue(candidates []approvalCandidate, queue submissionQueue) {
	fmt.Printf("Approval queue (%d candidates)\n", len(candidates))
	for _, c := range candidates {
		state := "pending"
		if c.approved {
			state = "submission_ready"
		}
		f := c.finding.Finding
		fmt.Printf("  [%-16s] %-40s gate=%-18s triage=%-12s %s %s\n",
			state, f.ID, c.finding.Status, c.verdict.Classification, strings.ToUpper(string(f.Severity)), f.Title)
	}
	fmt.Printf("\nsubmission_ready.json entries: %d\n", len(queue.Entries))
	for _, e := range queue.Entries {
		fmt.Printf("  %s  %s  (%s, approved %s)\n", e.FindingID, e.Title, e.GateVerdict, e.ApprovedAt.Format(time.RFC3339))
	}
	fmt.Println("\nApproval requires: scoutr submit --require-approval --finding <id> and typing APPROVE.")
}

// printApprovalSummary shows exactly what the human is approving.
func printApprovalSummary(f *findings.Finding, vf *validate.ValidatedFinding, verdict triage.Verdict, draftPath string, draftSize int) {
	fmt.Println("=== Approval summary (Tier 3) ===")
	fmt.Printf("Finding:        %s\n", f.ID)
	fmt.Printf("Title:          %s\n", f.Title)
	fmt.Printf("Severity:       %s (confidence %s)\n", strings.ToUpper(string(f.Severity)), f.Confidence)
	fmt.Printf("Target:         %s%s\n", f.Target, f.Path)
	fmt.Printf("Gate verdict:   %s  (7-Check Readiness Gate)\n", vf.Status)
	fmt.Printf("Triage:         %s (confidence %d, source %s)\n", verdict.Classification, verdict.Confidence, verdict.Source)
	if verdict.Rationale != "" {
		fmt.Printf("Rationale:      %s\n", verdict.Rationale)
	}
	if len(verdict.HardRuleOverrides) > 0 {
		fmt.Printf("Hard rules:     %s\n", strings.Join(verdict.HardRuleOverrides, ", "))
	}
	fmt.Printf("Draft:          %s (%d bytes)\n", draftPath, draftSize)
	fmt.Println()
	fmt.Println("--- Exact evidence bundle (from validated_findings.json) ---")
	fmt.Printf("Matched template / rule: %s\n", orDash(f.RuleID))
	if len(vf.AffectedPaths) > 0 {
		fmt.Printf("Affected paths: %s\n", strings.Join(vf.AffectedPaths, ", "))
	}
	printEvidenceBlock("Request (redacted)", f.Request)
	printEvidenceBlock("Response (redacted)", f.Response)
	printEvidenceBlock("Matched evidence", f.Evidence)
	for _, g := range vf.GateResults {
		status := "pass"
		if !g.Passed {
			status = "FAIL"
		}
		fmt.Printf("  gate %d %-32s %s %s\n", g.GateID, g.Name, status, g.Reason)
	}
	fmt.Println("--- end of evidence bundle ---")

	if verdict.Classification == triage.LikelyFalse {
		fmt.Println("\nWARNING: triage classified this as likely_false. Approve only if you have verified it by hand.")
	}
	if vf.Status == validate.StatusNeedsManualReview {
		fmt.Println("\nNOTE: the gate flagged this for manual review, so your confirmation is the only verification it has.")
	}
}

func printEvidenceBlock(label, body string) {
	if strings.TrimSpace(body) == "" {
		fmt.Printf("\n[%s]\n  (not captured)\n", label)
		return
	}
	fmt.Printf("\n[%s]\n%s\n", label, body)
}

func promptApproval(cmd *cobra.Command) (bool, error) {
	fmt.Printf("\nType APPROVE to mark this finding submission_ready (anything else cancels): ")
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	// A closed stdin (io.EOF with no content) is not a keystroke, so it can
	// never be consent: only the literal word APPROVE is.
	return strings.TrimSpace(line) == "APPROVE", nil
}

func loadSubmissionQueue(ws *workspace.Workspace) (submissionQueue, error) {
	queue := submissionQueue{Version: "1.0"}
	err := ws.LoadArtifact(workspace.SubmissionQueueFile, &queue)
	if err != nil {
		// A missing queue simply means nothing has been approved yet.
		if errors.Is(err, fs.ErrNotExist) {
			return submissionQueue{Version: "1.0"}, nil
		}
		return queue, fmt.Errorf("load %s: %w", workspace.SubmissionQueueFile, err)
	}
	if queue.Version == "" {
		queue.Version = "1.0"
	}
	return queue, nil
}

func saveSubmissionEntry(ws *workspace.Workspace, queue *submissionQueue, entry submissionEntry) error {
	replaced := false
	for i := range queue.Entries {
		if queue.Entries[i].FindingID == entry.FindingID {
			queue.Entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		queue.Entries = append(queue.Entries, entry)
	}
	queue.UpdatedAt = time.Now().UTC()
	return ws.SaveArtifact(workspace.SubmissionQueueFile, queue)
}

// draftFileNameFor is the single source of truth for draft file names: the
// drafting package owns the transform, submit only reads it.
func draftFileNameFor(vf *validate.ValidatedFinding) string {
	return draft.FileName(vf.Finding.ID)
}

// draftIdentity is the exact manifest line the drafting package renders for a
// finding. Matching the whole line avoids accepting a draft whose finding ID
// merely shares a prefix with the requested one.
func draftIdentity(findingID string) string {
	return "- **Finding ID:** `" + findingID + "`"
}

// sysUser reports the OS account for the approval audit trail. Windows sets
// USERNAME, POSIX sets USER or LOGNAME.
func sysUser() string {
	for _, key := range []string{"USER", "LOGNAME", "USERNAME"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
