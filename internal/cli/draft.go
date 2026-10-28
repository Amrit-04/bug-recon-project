package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/draft"
	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

// draftEntry is one row of the reports/drafts/index.md manifest.
type draftEntry struct {
	Rank           int
	FindingID      string
	Title          string
	Severity       string
	GateVerdict    string
	Classification triage.Classification
	FileName       string
}

// runReportDraft implements `scoutr report --draft`.
//
// It is Tier 2: the model may phrase the narrative sections, but it never
// decides which findings are real (triage ranks only) and it never produces
// the evidence block (that is copied from validated_findings.json). Nothing
// here can mark a finding submission-ready.
func runReportDraft(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	ctx := cmd.Context()

	if reportFromRun == "" {
		return fmt.Errorf("--draft requires --from <run-dir>: drafts are written to <run-dir>/%s", workspace.DraftsDir)
	}
	if cfg.OutputFile != "" {
		return fmt.Errorf("--draft writes one file per finding under %s; -o is not supported", workspace.DraftsDir)
	}

	ws, err := workspace.OpenRun(reportFromRun)
	if err != nil {
		return fmt.Errorf("open workspace: %w", err)
	}

	validated, err := ws.LoadValidatedFindings()
	if err != nil {
		return fmt.Errorf("load validated findings: %w", err)
	}
	if len(validated) == 0 {
		return fmt.Errorf("no validated findings in %s (run scoutr validate first)", reportFromRun)
	}

	var triageReport triage.Report
	if err := ws.LoadArtifact(workspace.TriageFile, &triageReport); err != nil {
		return fmt.Errorf("load %s: %w (run `scoutr triage --from %s` first)", workspace.TriageFile, err, reportFromRun)
	}
	if len(triageReport.Verdicts) == 0 {
		return fmt.Errorf("%s contains no verdicts; re-run scoutr triage", workspace.TriageFile)
	}

	client, err := buildLLMClient()
	if err != nil {
		return err
	}

	// Index the gate's output so a verdict can never select a finding the gate
	// did not produce, and a suppressed finding can never be drafted.
	byID := make(map[string]*validate.ValidatedFinding, len(validated))
	for _, vf := range validated {
		if vf == nil || vf.Finding == nil {
			continue
		}
		byID[vf.Finding.ID] = vf
	}

	builder := &draft.Builder{
		Client:   client,
		Model:    llmModelName(),
		MaxChars: triage.DefaultMaxEvidenceChars,
	}
	techByHost := loadTechMap(ws)

	fmt.Printf("Tier 2 drafting: %d findings, provider=%s model=%s\n", len(triageReport.Verdicts), triageReport.Provider, triageReport.Model)
	fmt.Println("Ordering comes from triage.json; content and evidence come from validated_findings.json.")
	fmt.Println()

	var entries []draftEntry
	var skipped int
	// File names are the join key `scoutr submit` uses to find a draft, so a
	// collision must be reported rather than silently renamed.
	usedNames := map[string]string{}

	// triage.json is already rank-sorted, so this loop is the report ordering.
	for _, verdict := range triageReport.Verdicts {
		if verdict.Classification != triage.LikelyTrue && verdict.Classification != triage.NeedsHuman {
			skipped++
			continue
		}
		vf, ok := byID[verdict.FindingID]
		if !ok {
			skipped++
			if cfg.Verbose {
				fmt.Printf("  skip %s: not present in validated_findings.json\n", verdict.FindingID)
			}
			continue
		}
		if vf.Status == validate.StatusSuppressed {
			skipped++
			continue
		}

		d, err := builder.Build(ctx, draft.Request{
			Finding:    vf,
			Verdict:    verdict,
			Technology: techByHost[triage.HostKey(vf.Finding.Target)],
		})
		if err != nil {
			return fmt.Errorf("draft %s: %w", verdict.FindingID, err)
		}

		fileName := d.FileName
		if fileName == workspace.DraftIndexFile {
			return fmt.Errorf("finding %s maps to %q, which is reserved for the draft manifest", verdict.FindingID, fileName)
		}
		if prev, dup := usedNames[fileName]; dup {
			return fmt.Errorf("findings %s and %s both map to draft file %q; submit resolves drafts by file name, so rename one finding ID", prev, verdict.FindingID, fileName)
		}
		usedNames[fileName] = verdict.FindingID
		path, err := ws.SaveDraft(fileName, d.Markdown)
		if err != nil {
			return fmt.Errorf("save draft %s: %w", verdict.FindingID, err)
		}

		entries = append(entries, draftEntry{
			Rank:           verdict.Rank,
			FindingID:      d.FindingID,
			Title:          d.Title,
			Severity:       strings.ToUpper(verdict.Severity),
			GateVerdict:    string(d.GateVerdict),
			Classification: d.Classification,
			FileName:       fileName,
		})
		fmt.Printf("  #%d [%s] %s -> %s\n", verdict.Rank, d.Classification, d.FindingID, path)
	}

	if len(entries) == 0 {
		return fmt.Errorf("no findings eligible for drafting (need a triage classification of %q or %q and a non-suppressed gate verdict)",
			triage.LikelyTrue, triage.NeedsHuman)
	}

	indexPath, err := ws.SaveDraft(workspace.DraftIndexFile, renderDraftIndex(entries, triageReport, skipped, client != nil))
	if err != nil {
		return fmt.Errorf("save draft index: %w", err)
	}

	fmt.Printf("\nDrafted %d findings (skipped %d).\n", len(entries), skipped)
	fmt.Printf("Draft manifest: %s\n", indexPath)
	fmt.Println("\nThese drafts are NOT submission-ready and were not sent anywhere.")
	fmt.Printf("A human must run: scoutr submit --require-approval --from %s\n", reportFromRun)
	return nil
}

// renderDraftIndex builds reports/drafts/index.md. It is a manifest, not a
// report: the authoritative report is still generated from validated findings.
func renderDraftIndex(entries []draftEntry, report triage.Report, skipped int, usedModel bool) string {
	var b strings.Builder
	b.WriteString("# Draft manifest (Tier 2, human review required)\n\n")
	b.WriteString("> Ordering is taken from `triage.json`. Content and evidence come from `validated_findings.json`.\n")
	b.WriteString("> The 7-Check gate verdict is shown unchanged. No draft is submission-ready.\n\n")
	b.WriteString(fmt.Sprintf("- Triage provider: `%s` (model `%s`)\n", report.Provider, report.Model))
	b.WriteString(fmt.Sprintf("- Drafted findings: %d\n", len(entries)))
	b.WriteString(fmt.Sprintf("- Skipped findings (likely_false, unmapped or suppressed): %d\n", skipped))
	if !usedModel {
		b.WriteString("- Model drafting: **disabled** (`--no-llm`); narrative fields are NEEDS_HUMAN_INPUT\n")
	}
	b.WriteString("\n| Rank | Finding | Severity | Gate verdict | Triage | Draft |\n")
	b.WriteString("|------|---------|----------|--------------|--------|-------|\n")

	sorted := append([]draftEntry{}, entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Rank < sorted[j].Rank })
	for _, e := range sorted {
		b.WriteString(fmt.Sprintf("| %d | `%s` %s | %s | %s | %s | [%s](%s) |\n",
			e.Rank, e.FindingID, tableCell(e.Title), e.Severity, e.GateVerdict, e.Classification, e.FileName, e.FileName))
	}

	b.WriteString("\n## Next step\n\n")
	b.WriteString("Run `scoutr submit --require-approval --from <run-dir>` for each finding you want to queue.\n")
	b.WriteString("That command prints the evidence bundle and requires you to type `APPROVE`. scoutr never submits to a platform.\n")
	return b.String()
}

// tableCell keeps a title from breaking out of its Markdown table cell.
func tableCell(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "|", "\\|")
}
