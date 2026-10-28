package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	validateFromRun string
	validateInput   string
	validateTriage  bool
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Score and filter findings through the 7-Check Readiness Gate",
	Long: `Eliminates false positives and verifies reproducibility through the 7-Check Readiness Gate:

1. Scope Verification: Exact host and endpoint confirmed in-scope.
2. Soft-404 / Baseline Diff: Distinguishes actual files from catch-all HTML / SPA fallbacks.
3. Content Signature Match: Matches structural signatures (e.g. .git/HEAD refs, .env KEY=val).
4. Impact Classification: Downgrades benign missing headers on static assets.
5. Evidence Completeness: Enforces reproducible snippets and redacts sensitive credentials.
6. Deduplication & Root-Cause Grouping: Aggregates repeated errors across paths on same host.
7. Remediation Mapping: Enriches findings with concrete remediation, CWE, and OWASP references.

Categorizes findings into: Verified, NeedsManualReview, and Suppressed.
`,
	Example: `  scoutr validate --scope scope.yaml -i raw_findings.jsonl -o validated.jsonl
  scoutr validate --from .scoutr/runs/example.com-20261024-120000`,
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVar(&validateFromRun, "from", "", "Load raw findings from existing workspace run directory")
	validateCmd.Flags().StringVarP(&validateInput, "input", "i", "", "Input findings file (JSONL format)")
	validateCmd.Flags().BoolVar(&validateTriage, "triage", false,
		"Run Tier 2 LLM triage immediately after the gate (requires --from, keeps triage.json separate)")
	addLLMFlags(validateCmd)
	RootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	ctx := cmd.Context()

	var s *scope.Scope
	if cfg.ScopeFile != "" {
		var err error
		s, err = scope.LoadFromFile(cfg.ScopeFile)
		if err != nil {
			return fmt.Errorf("load scope: %w", err)
		}
	}

	var rawFindings []*findings.Finding
	var ws *workspace.Workspace

	// 1. Loading from workspace run
	if validateFromRun != "" {
		var err error
		ws, err = workspace.OpenRun(validateFromRun)
		if err != nil {
			return fmt.Errorf("open workspace: %w", err)
		}
		rawFindings, err = ws.LoadRawFindings()
		if err != nil {
			return fmt.Errorf("load raw findings from workspace: %w", err)
		}
		fmt.Printf("Loaded %d raw findings from workspace: %s\n", len(rawFindings), validateFromRun)
	} else {
		// 2. Loading from input file or stdin
		var in *os.File
		if validateInput != "" {
			var err error
			in, err = os.Open(validateInput)
			if err != nil {
				return fmt.Errorf("open input file: %w", err)
			}
			defer in.Close()
		} else {
			in = os.Stdin
		}

		scanner := bufio.NewScanner(in)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var f findings.Finding
			if err := json.Unmarshal([]byte(line), &f); err == nil && f.ID != "" {
				rawFindings = append(rawFindings, &f)
			}
		}
	}

	if len(rawFindings) == 0 {
		return fmt.Errorf("no raw findings provided to validate")
	}

	validator := validate.NewValidator(s)
	validated := validator.ValidateAndGroup(ctx, rawFindings)

	var verifiedCount, reviewCount, suppressedCount int
	for _, vf := range validated {
		switch vf.Status {
		case validate.StatusVerified:
			verifiedCount++
		case validate.StatusNeedsManualReview:
			reviewCount++
		case validate.StatusSuppressed:
			suppressedCount++
		}
	}

	fmt.Printf("\n7-Check Gate Validation Results:\n")
	fmt.Printf("  * Verified Findings:     %d\n", verifiedCount)
	fmt.Printf("  * Needs Manual Review:   %d\n", reviewCount)
	fmt.Printf("  * Suppressed (False +):  %d\n", suppressedCount)
	fmt.Printf("  * Total After Grouping:  %d\n\n", len(validated))

	// Save back to workspace if active
	if ws != nil {
		if err := ws.SaveValidatedFindings(validated); err != nil {
			return fmt.Errorf("save validated findings to workspace: %w", err)
		}
		fmt.Printf("Saved validated findings to: %s/%s\n", ws.Dir, workspace.ValidatedFindingsFile)
	}

	// Write output to file if requested
	if cfg.OutputFile != "" {
		out, err := os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer out.Close()

		encoder := json.NewEncoder(out)
		for _, vf := range validated {
			if err := encoder.Encode(vf); err != nil {
				return fmt.Errorf("encode validated finding: %w", err)
			}
		}
		fmt.Printf("Wrote validated output to: %s\n", cfg.OutputFile)
	}

	// Optional Tier 2 step: triage runs strictly AFTER the gate has written its
	// verdicts, reads only validated_findings.json and writes a separate artifact.
	if validateTriage {
		if ws == nil {
			return fmt.Errorf("--triage requires --from <run-dir> so triage.json is stored in the workspace")
		}
		report, err := runTriageForWorkspace(ctx, ws, cfg.Verbose)
		if err != nil {
			return fmt.Errorf("triage after validation: %w", err)
		}
		fmt.Printf("Saved triage results to: %s/%s\n", ws.Dir, workspace.TriageFile)
		printTriageSummary(report)
	}

	return nil
}
