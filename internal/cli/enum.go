package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/recon/subdomains"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate subdomains (passive and/or brute force)",
	Long: `Enumerate subdomains for targets in scope using passive and/or active methods.

Passive methods:
  - crt.sh (certificate transparency logs)
  - External passive tools via --external (subfinder, amass, assetfinder, dnsx)

Active methods (opt-in):
  - DNS brute force using a wordlist (default embedded or custom --wordlist)
`,
	Example: `  scoutr enum --scope scope.yaml -o subs.jsonl
  scoutr enum --scope scope.yaml --passive-only -o passive.jsonl
  scoutr enum --scope scope.yaml --external -o subs.jsonl
  scoutr enum --scope scope.yaml --brute --wordlist subs.txt -o brute.jsonl`,
	RunE: runEnum,
}

func init() {
	enumCmd.Flags().BoolVar(&globalConfig.External, "external", false,
		"Merge results from available external passive tools (subfinder, amass, assetfinder, dnsx)")
}

func runEnum(cmd *cobra.Command, args []string) error {
	cfg := globalConfig

	// Validate scope file
	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}

	// Load scope
	s, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	ctx := cmd.Context()
	runner := tools.NewExecRunner()
	logger := func(format string, args ...any) {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	// Dry-run mode
	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s (in_scope: %v)\n", cfg.ScopeFile, s.InScope)
		if cfg.External {
			rootDomains := tools.ExtractRootDomains(s)
			fmt.Fprintf(os.Stderr, "[DRY-RUN] Would run external tools (subfinder, amass, assetfinder, dnsx) for root domains: %v\n", rootDomains)
		}
		if !cfg.Brute || !cfg.PassiveOnly {
			fmt.Fprintf(os.Stderr, "[DRY-RUN] Would query crt.sh certificate transparency logs\n")
		}
		if cfg.Brute {
			fmt.Fprintf(os.Stderr, "[DRY-RUN] Would run DNS brute force\n")
		}
		return nil
	}

	// Open output file
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

	// Collect all found hosts
	found := make(map[string]bool)

	// 1. Passive enumeration via crt.sh (default unless --brute only)
	if !cfg.Brute || !cfg.PassiveOnly {
		if hosts, err := subdomains.FromCRTSH(ctx, s); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: passive enum via crt.sh failed: %v\n", err)
		} else {
			for _, h := range hosts {
				if s.IsInScope(h) {
					found[h] = true
				}
			}
		}
	}

	// 2. External passive tools (subfinder, amass, assetfinder, dnsx)
	if cfg.External {
		rootDomains := tools.ExtractRootDomains(s)
		logger("[INFO] Querying external passive tools for root domains: %v", rootDomains)

		// subfinder
		if sfHosts, err := tools.RunSubfinder(ctx, runner, s, rootDomains, logger); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: subfinder failed: %v\n", err)
		} else {
			for _, h := range sfHosts {
				if s.IsInScope(h) {
					found[h] = true
				}
			}
		}

		// amass
		if amassHosts, err := tools.RunAmass(ctx, runner, s, rootDomains, logger); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: amass failed: %v\n", err)
		} else {
			for _, h := range amassHosts {
				if s.IsInScope(h) {
					found[h] = true
				}
			}
		}

		// assetfinder
		if afHosts, err := tools.RunAssetfinder(ctx, runner, s, rootDomains, logger); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: assetfinder failed: %v\n", err)
		} else {
			for _, h := range afHosts {
				if s.IsInScope(h) {
					found[h] = true
				}
			}
		}

		// dnsx verification of all discovered subdomains
		if len(found) > 0 {
			var hostList []string
			for h := range found {
				hostList = append(hostList, h)
			}
			if dnsxResults, err := tools.RunDNSX(ctx, runner, s, hostList, int(cfg.Rate), logger); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: dnsx resolution failed: %v\n", err)
			} else if len(dnsxResults) > 0 {
				for _, res := range dnsxResults {
					if res.Host != "" && s.IsInScope(res.Host) {
						found[res.Host] = true
					}
				}
			}
		}
	}

	// 3. DNS brute force (opt-in with --brute)
	if cfg.Brute {
		wordlist := cfg.Wordlist
		if wordlist == "" {
			wordlist = subdomains.DefaultWordlistPath
		}
		if hosts, err := subdomains.BruteForce(ctx, s, wordlist); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: DNS brute force failed: %v\n", err)
		} else {
			for _, h := range hosts {
				if s.IsInScope(h) {
					found[h] = true
				}
			}
		}
	}

	// Write results as JSONL (one JSON object per line)
	encoder := json.NewEncoder(out)
	for host := range found {
		if err := encoder.Encode(map[string]string{"host": host}); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Found %d unique subdomains\n", len(found))
	return nil
}
