package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	fuzzInputFile  string
	fuzzFromRun    string
	fuzzMaxTargets int
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Curated content/path discovery via ffuf (Tier 1)",
	Long: `Run content and path discovery with a deliberately small, curated wordlist.

Safety constraints:
  - The embedded wordlist is short on purpose (common admin/api/backup paths).
    Brute-force-everything dictionaries are not used.
  - The per-host rate limit is passed to ffuf as -rate with 5 threads.
  - Query-string URLs are skipped: path discovery must not mutate state.
  - ffuf writes structured JSON (-of json) which scoutr parses into URL,
    status code, content length, line count and redirect location.
  - Targets are capped (--max-targets, default 25) and scope-checked before
    and after execution.

Discovered URLs are candidates only. Feed them into nuclei / the 7-Check gate;
they are never treated as verified findings.
`,
	Example: `  scoutr fuzz --scope scope.yaml -i live.jsonl -o candidates.jsonl
  scoutr fuzz --scope scope.yaml --from .scoutr/runs/example.com-20261028-101500`,
	RunE: runFuzz,
}

func init() {
	fuzzCmd.Flags().StringVarP(&fuzzInputFile, "input", "i", "", "Input file of live hosts/URLs (JSONL)")
	fuzzCmd.Flags().StringVar(&fuzzFromRun, "from", "", "Workspace run directory (reads httpx.json, writes fuzz.json)")
	fuzzCmd.Flags().IntVar(&fuzzMaxTargets, "max-targets", tools.DefaultMaxFFUFTargets, "Maximum number of hosts to fuzz")
	RootCmd.AddCommand(fuzzCmd)
}

func runFuzz(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	ctx := cmd.Context()

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}
	s, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	var ws *workspace.Workspace
	var targets []string

	if fuzzFromRun != "" {
		ws, err = workspace.OpenRun(fuzzFromRun)
		if err != nil {
			return fmt.Errorf("open workspace: %w", err)
		}
		var live []tools.HTTPXResult
		if err := ws.LoadArtifact(workspace.HTTPXFile, &live); err == nil {
			for _, l := range live {
				targets = append(targets, l.URL)
			}
		} else {
			targets, err = ws.LoadInventory()
			if err != nil {
				return fmt.Errorf("load inventory: %w", err)
			}
		}
	} else {
		targets, err = readTargetsFromInput(fuzzInputFile)
		if err != nil {
			return err
		}
	}

	targets = tools.FilterTargetsInScope(s, targets)
	if len(targets) == 0 {
		return fmt.Errorf("no in-scope targets to fuzz")
	}

	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s\n", cfg.ScopeFile)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would run ffuf with the embedded curated wordlist on %d hosts (cap %d, rate %d/s)\n",
			len(targets), fuzzMaxTargets, int(cfg.RatePerHost))
		return nil
	}

	runner := tools.NewExecRunner()
	logger := loggerFor(cfg.Verbose)

	results, err := tools.RunFFUF(ctx, runner, s, targets, int(cfg.RatePerHost), fuzzMaxTargets, logger)
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Warning: ffuf failed: %v\n", err)
	}

	if ws != nil {
		if err := ws.SaveArtifact(workspace.FuzzFile, results); err != nil {
			return fmt.Errorf("save fuzz artifact: %w", err)
		}
		fmt.Printf("Saved %d discovered paths to: %s/%s\n", len(results), ws.Dir, workspace.FuzzFile)
	}

	if cfg.OutputFile != "" {
		values := make([]any, 0, len(results))
		for _, r := range results {
			values = append(values, r)
		}
		if err := writeJSONL(cfg.OutputFile, values); err != nil {
			return err
		}
		fmt.Printf("Wrote %d path candidates to %s\n", len(results), cfg.OutputFile)
	}

	fmt.Printf("Content discovery complete: %d candidate paths (candidates only, not findings)\n", len(results))
	return nil
}
