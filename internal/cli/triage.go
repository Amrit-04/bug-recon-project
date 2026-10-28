package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	triageFromRun      string
	triageInput        string
	triageBatchSize    int
	triageExplainRules bool
)

var triageCmd = &cobra.Command{
	Use:   "triage",
	Short: "Rank validated findings with a local LLM (Tier 2, agent-assisted)",
	Long: `Rank findings that the 7-Check Readiness Gate has already classified.

What this command does:
  - reads validated_findings.json (the source of truth produced by
    scoutr validate) and, optionally, httpx.json for technology fingerprints
  - batches findings (default 12, max 20) into structured JSON prompts
  - asks a local model for one of exactly three classifications per finding:
    likely_true, likely_false or needs_human, with rationale and confidence
  - applies the deterministic hard-rule layer, which can only turn
    likely_false into needs_human
  - writes tier2/triage.json as a SEPARATE artifact

What this command cannot do:
  - it never sees the scope file, never selects targets and never runs tools
  - it never changes a gate verdict (Verified / NeedsManualReview / Suppressed)
  - it never suppresses a finding: if the model is unavailable, every finding
    falls back to needs_human
  - its output never becomes report content; only report ordering

Tier 2 never authorizes submission. A human must run
scoutr submit --require-approval afterwards.
`,
	Example: `  scoutr triage --from .scoutr/runs/example.com-20261028-101500 --llm-model llama3.2
  scoutr triage --from .scoutr/runs/example.com-20261028-101500 --no-llm
  scoutr triage -i validated_findings.json --llm-model qwen2.5:7b --batch-size 8`,
	RunE: runTriage,
}

func init() {
	triageCmd.Flags().StringVar(&triageFromRun, "from", "", "Workspace run directory containing validated_findings.json")
	triageCmd.Flags().StringVarP(&triageInput, "input", "i", "", "Input JSONL file of validated findings (alternative to --from)")
	triageCmd.Flags().IntVar(&triageBatchSize, "batch-size", triage.DefaultBatchSize, "Findings per LLM call (1-20)")
	triageCmd.Flags().BoolVar(&triageExplainRules, "explain-rules", false, "Print the deterministic hard-rule documentation and exit")
	addLLMFlags(triageCmd)
	RootCmd.AddCommand(triageCmd)
}

func runTriage(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	ctx := cmd.Context()

	if triageExplainRules {
		fmt.Println(triage.HardRuleDocumentation())
		return nil
	}

	var ws *workspace.Workspace
	var list []*validate.ValidatedFinding
	var err error

	switch {
	case triageFromRun != "":
		ws, err = workspace.OpenRun(triageFromRun)
		if err != nil {
			return fmt.Errorf("open workspace: %w", err)
		}
		list, err = ws.LoadValidatedFindings()
		if err != nil {
			return fmt.Errorf("load validated findings: %w", err)
		}
	case triageInput != "":
		list, err = loadValidatedJSONL(triageInput)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("either --from <run-dir> or --input <validated.jsonl> is required")
	}

	if len(list) == 0 {
		return fmt.Errorf("no validated findings to triage (run scoutr validate first)")
	}

	client, err := buildLLMClient()
	if err != nil {
		return err
	}

	opts := triage.Options{
		Client:    client,
		Model:     llmModelName(),
		BatchSize: triageBatchSize,
		Log:       triage.LogFunc(loggerFor(cfg.Verbose)),
	}
	report, err := triage.Run(ctx, list, loadTechMap(ws), opts)
	if err != nil {
		return fmt.Errorf("triage: %w", err)
	}

	if ws != nil {
		if err := ws.SaveArtifact(workspace.TriageFile, report); err != nil {
			return fmt.Errorf("save triage artifact: %w", err)
		}
		fmt.Printf("Saved triage results to: %s/%s\n", ws.Dir, workspace.TriageFile)
	}

	printTriageSummary(report)

	if cfg.OutputFile != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal triage report: %w", err)
		}
		if err := os.WriteFile(cfg.OutputFile, data, 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		fmt.Printf("Wrote triage JSON to %s\n", cfg.OutputFile)
	}

	fmt.Println("\ntriage.json is ranking only. validated_findings.json remains the report source of truth.")
	fmt.Println("A human must review before anything is marked submission_ready.")
	return nil
}

// runTriageForWorkspace is the shared entry point used by `scoutr validate
// --triage` so triage always runs directly after the validation gate.
func runTriageForWorkspace(ctx context.Context, ws *workspace.Workspace, verbose bool) (*triage.Report, error) {
	list, err := ws.LoadValidatedFindings()
	if err != nil {
		return nil, fmt.Errorf("load validated findings: %w", err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no validated findings to triage")
	}

	client, err := buildLLMClient()
	if err != nil {
		return nil, err
	}

	report, err := triage.Run(ctx, list, loadTechMap(ws), triage.Options{
		Client:    client,
		Model:     llmModelName(),
		BatchSize: triageBatchSize,
		Log:       triage.LogFunc(loggerFor(verbose)),
	})
	if err != nil {
		return nil, err
	}

	if err := ws.SaveArtifact(workspace.TriageFile, report); err != nil {
		return nil, fmt.Errorf("save triage artifact: %w", err)
	}
	return report, nil
}

// loadValidatedJSONL reads validated findings from a JSONL file.
func loadValidatedJSONL(path string) ([]*validate.ValidatedFinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()

	var list []*validate.ValidatedFinding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), tools.MaxScanLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var vf validate.ValidatedFinding
		if err := json.Unmarshal([]byte(line), &vf); err == nil && vf.Finding != nil {
			list = append(list, &vf)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return list, nil
}

// loadTechMap builds host -> technology fingerprints from httpx.json if the
// workspace has one. Technology is optional context for the model.
func loadTechMap(ws *workspace.Workspace) map[string][]string {
	if ws == nil {
		return nil
	}
	var live []tools.HTTPXResult
	if err := ws.LoadArtifact(workspace.HTTPXFile, &live); err != nil {
		return nil
	}
	tech := make(map[string][]string, len(live))
	for _, l := range live {
		if len(l.Tech) == 0 {
			continue
		}
		tech[triage.HostKey(l.URL)] = l.Tech
		if l.Host != "" {
			tech[triage.HostKey(l.Host)] = l.Tech
		}
	}
	return tech
}

// printTriageSummary renders the operator-facing triage table.
func printTriageSummary(report *triage.Report) {
	fmt.Printf("\nTier 2 triage (provider=%s model=%s batches=%d)\n", report.Provider, report.Model, report.Batches)
	fmt.Printf("  likely_true:  %d\n", report.Counts[string(triage.LikelyTrue)])
	fmt.Printf("  needs_human:  %d\n", report.Counts[string(triage.NeedsHuman)])
	fmt.Printf("  likely_false: %d\n", report.Counts[string(triage.LikelyFalse)])
	fmt.Printf("  suppressed findings excluded from triage: %d\n", report.ExcludedSuppressed)
	if len(report.LLMErrors) > 0 {
		fmt.Printf("  LLM errors: %d (see triage.json; affected findings defaulted to needs_human)\n", len(report.LLMErrors))
	}

	limit := len(report.Verdicts)
	if limit > 10 {
		limit = 10
	}
	if limit == 0 {
		return
	}
	fmt.Println("\nTop-ranked findings:")
	for _, v := range report.Verdicts[:limit] {
		fmt.Printf("  #%d [%s] %s %s — %s\n", v.Rank, v.Classification, strings.ToUpper(v.Severity), v.FindingID, v.Title)
		fmt.Printf("       target: %s\n", v.Target)
		fmt.Printf("       gate: %s | confidence: %d%% | source: %s\n", v.GateVerdict, v.Confidence, v.Source)
		if v.Rationale != "" {
			fmt.Printf("       rationale: %s\n", v.Rationale)
		}
		if v.NextManualTest != "" {
			fmt.Printf("       next manual test: %s\n", v.NextManualTest)
		}
		if len(v.HardRuleOverrides) > 0 {
			fmt.Printf("       hard rules applied: %s\n", strings.Join(v.HardRuleOverrides, ", "))
		}
	}
}
