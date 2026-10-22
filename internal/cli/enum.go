package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/recon/subdomains"
	"github.com/scoutr/scoutr/internal/scope"
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate subdomains (passive and/or brute force)",
	Long: `Enumerate subdomains for targets in scope using passive and/or active methods.

Passive methods:
  - crt.sh (certificate transparency logs)

Active methods (opt-in):
  - DNS brute force using a wordlist (default embedded or custom --wordlist)
`,
	Example: `  scoutr enum --scope scope.yaml -o subs.jsonl
  scoutr enum --scope scope.yaml --passive-only -o passive.jsonl
  scoutr enum --scope scope.yaml --brute --wordlist subs.txt -o brute.jsonl`,
	RunE: runEnum,
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

	ctx := cmd.Context()

	// Collect all found hosts
	found := make(map[string]bool)

	// Passive enumeration via crt.sh (default unless --brute only)
	if !cfg.Brute || !cfg.PassiveOnly {
		if hosts, err := subdomains.FromCRTSH(ctx, s); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: passive enum via crt.sh failed: %v\n", err)
		} else {
			for _, h := range hosts {
				found[h] = true
			}
		}
	}

	// DNS brute force (opt-in with --brute)
	if cfg.Brute {
		wordlist := cfg.Wordlist
		if wordlist == "" {
			wordlist = subdomains.DefaultWordlistPath
		}
		if hosts, err := subdomains.BruteForce(ctx, s, wordlist); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: DNS brute force failed: %v\n", err)
		} else {
			for _, h := range hosts {
				found[h] = true
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

	fmt.Printf("Found %d unique subdomains\n", len(found))
	return nil
}
