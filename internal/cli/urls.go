package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
)

var urlsCmd = &cobra.Command{
	Use:   "urls",
	Short: "Gather historical endpoints from web archive APIs (waybackurls/gau)",
	Long: `Collects historical URLs and endpoints for in-scope domains using public web archives.

Passive sources:
  - gau (AlienVault, Wayback, Common Crawl, URLScan)
  - waybackurls (Wayback Machine)

Zero direct traffic is sent to target infrastructure. All discovered URLs are strictly
filtered through scope.yaml before output.
`,
	Example: `  scoutr urls --scope scope.yaml -o urls.jsonl
  scoutr urls --scope scope.yaml --dry-run`,
	RunE: runURLs,
}

func init() {
	RootCmd.AddCommand(urlsCmd)
}

func runURLs(cmd *cobra.Command, args []string) error {
	cfg := globalConfig

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}

	s, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	rootDomains := tools.ExtractRootDomains(s)
	if len(rootDomains) == 0 {
		return fmt.Errorf("no in-scope root domains found in %s", cfg.ScopeFile)
	}

	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s (in_scope: %v)\n", cfg.ScopeFile, s.InScope)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would fetch historical URLs for domains: %v\n", rootDomains)
		return nil
	}

	runner := tools.NewExecRunner()
	logger := func(format string, args ...any) {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	ctx := cmd.Context()
	urls, err := tools.RunURLs(ctx, runner, s, rootDomains, logger)
	if err != nil {
		return fmt.Errorf("retrieve archive urls: %w", err)
	}

	var out *os.File
	if cfg.OutputFile != "" {
		out, err = os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	encoder := json.NewEncoder(out)
	for _, u := range urls {
		if err := encoder.Encode(map[string]string{"url": u}); err != nil {
			return fmt.Errorf("write url output: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Collected %d unique in-scope archive URLs\n", len(urls))
	return nil
}
