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
	xssInputFile  string
	xssFromRun    string
	xssMaxTargets int
)

var xssCmd = &cobra.Command{
	Use:   "xss",
	Short: "XSS probing via dalfox --deep-domxss (Tier 1, candidates only)",
	Long: `Probe parameterised, in-scope endpoints for reflected/DOM XSS.

Safety constraints:
  - Only URLs that contain query parameters are probed.
  - dalfox runs with --deep-domxss (headless DOM verification), --worker 1 and
    a --delay derived from --rate-per-host, so the existing per-host rate
    limiter is enforced for the whole run.
  - The target list is capped (--max-targets, default 50) and scope-checked.

Every result is written as a LOW-CONFIDENCE candidate finding. It is not a
verified vulnerability: the 7-Check Readiness Gate and a human reviewer decide
whether it survives.
`,
	Example: `  scoutr xss --scope scope.yaml -i crawled.jsonl -o xss_candidates.jsonl
  scoutr xss --scope scope.yaml --from .scoutr/runs/example.com-20261028-101500`,
	RunE: runXSS,
}

func init() {
	xssCmd.Flags().StringVarP(&xssInputFile, "input", "i", "", "Input file of parameterised URLs (JSONL)")
	xssCmd.Flags().StringVar(&xssFromRun, "from", "", "Workspace run directory (reads crawl.json/fuzz.json, appends to raw_findings.json)")
	xssCmd.Flags().IntVar(&xssMaxTargets, "max-targets", tools.DefaultMaxDalfoxTargets, "Maximum number of endpoints to probe")
	RootCmd.AddCommand(xssCmd)
}

func runXSS(cmd *cobra.Command, args []string) error {
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
	var urls []string

	if xssFromRun != "" {
		ws, err = workspace.OpenRun(xssFromRun)
		if err != nil {
			return fmt.Errorf("open workspace: %w", err)
		}

		var crawled []tools.KatanaResult
		if err := ws.LoadArtifact(workspace.CrawlFile, &crawled); err == nil {
			for _, c := range crawled {
				urls = append(urls, c.Endpoint)
			}
		}
		var fuzzed []tools.FFUFResult
		if err := ws.LoadArtifact(workspace.FuzzFile, &fuzzed); err == nil {
			for _, f := range fuzzed {
				urls = append(urls, f.URL)
			}
		}
		if len(urls) == 0 {
			fmt.Fprintln(os.Stderr, "Warning: no crawl.json/fuzz.json endpoints in run directory; pass -i instead")
		}
	} else {
		urls, err = readTargetsFromInput(xssInputFile)
		if err != nil {
			return err
		}
	}

	if len(urls) == 0 {
		return fmt.Errorf("no endpoints supplied for XSS probing")
	}

	parameterised := 0
	for _, u := range urls {
		if tools.IsParameterisedURL(u) {
			parameterised++
		}
	}

	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s\n", cfg.ScopeFile)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would run dalfox --deep-domxss on up to %d of %d parameterised endpoints (delay from %.1f rps)\n",
			xssMaxTargets, parameterised, cfg.RatePerHost)
		return nil
	}

	runner := tools.NewExecRunner()
	logger := loggerFor(cfg.Verbose)

	candidates, err := tools.RunDalfox(ctx, runner, s, urls, int(cfg.RatePerHost), xssMaxTargets, logger)
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Warning: dalfox probing failed: %v\n", err)
	}

	if ws != nil && len(candidates) > 0 {
		added, err := appendRawFindings(ws, candidates)
		if err != nil {
			return fmt.Errorf("persist dalfox candidates: %w", err)
		}
		fmt.Printf("Appended %d new dalfox candidates to: %s/%s\n", added, ws.Dir, workspace.RawFindingsFile)
	}

	if cfg.OutputFile != "" {
		values := make([]any, 0, len(candidates))
		for _, c := range candidates {
			values = append(values, c)
		}
		if err := writeJSONL(cfg.OutputFile, values); err != nil {
			return err
		}
		fmt.Printf("Wrote %d candidate findings to %s\n", len(candidates), cfg.OutputFile)
	}

	fmt.Printf("XSS probing complete: %d candidates (must pass scoutr validate before reporting)\n", len(candidates))
	return nil
}
