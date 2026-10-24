package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
)

var (
	crawlInputFile string
	crawlDepth     int
)

var crawlCmd = &cobra.Command{
	Use:   "crawl",
	Short: "Run shallow, scope-constrained link discovery via katana",
	Long: `Discovers web links and endpoints using katana with strict scope constraints.

Safety constraints:
  - Strict depth limitation (default: 2)
  - Explicit crawl-scope (-cs) and crawl-out-of-scope (-cos) regex from scope.yaml
  - Rate limited according to --rate
  - No active form submission or fuzzing
`,
	Example: `  scoutr crawl --scope scope.yaml -i live.jsonl -o crawled.jsonl
  scoutr crawl --scope scope.yaml --depth 1 -o links.jsonl
  scoutr crawl --scope scope.yaml --dry-run`,
	RunE: runCrawl,
}

func init() {
	crawlCmd.Flags().StringVarP(&crawlInputFile, "input", "i", "", "Input file of hosts/URLs to crawl (optional)")
	crawlCmd.Flags().IntVar(&crawlDepth, "depth", 2, "Maximum crawling depth")
	RootCmd.AddCommand(crawlCmd)
}

func runCrawl(cmd *cobra.Command, args []string) error {
	cfg := globalConfig

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}

	s, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	// Determine targets
	var targets []string
	if crawlInputFile != "" {
		f, err := os.Open(crawlInputFile)
		if err != nil {
			return fmt.Errorf("open input file: %w", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// Attempt JSON parsing (e.g. {"url": "..."} or {"host": "..."})
			var parsed map[string]string
			if err := json.Unmarshal([]byte(line), &parsed); err == nil {
				if u, ok := parsed["url"]; ok && u != "" {
					line = u
				} else if h, ok := parsed["host"]; ok && h != "" {
					line = h
				}
			}
			targets = append(targets, line)
		}
	} else {
		// Default to in-scope root domains formatted as https:// URLs
		rootDomains := tools.ExtractRootDomains(s)
		for _, d := range rootDomains {
			targets = append(targets, "https://"+d)
		}
	}

	targets = tools.FilterTargetsInScope(s, targets)
	if len(targets) == 0 {
		return fmt.Errorf("no valid in-scope targets to crawl")
	}

	if cfg.DryRun {
		cs, cos := tools.BuildScopeRegex(s)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s\n", cfg.ScopeFile)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would crawl targets: %v (depth: %d, rate: %.0f)\n", targets, crawlDepth, cfg.Rate)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Katana scope regex: -cs %q -cos %q\n", cs, cos)
		return nil
	}

	runner := tools.NewExecRunner()
	logger := func(format string, args ...any) {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	ctx := cmd.Context()
	results, err := tools.RunKatana(ctx, runner, s, targets, int(cfg.Rate), crawlDepth, logger)
	if err != nil {
		return fmt.Errorf("crawl failed: %w", err)
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
	for _, res := range results {
		if err := encoder.Encode(res); err != nil {
			return fmt.Errorf("write crawl output: %w", err)
		}
	}

	fmt.Printf("Discovered %d in-scope crawl endpoints\n", len(results))
	return nil
}
