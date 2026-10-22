package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/scope"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security checks against live hosts",
	Long: `Run security checks against a list of live hosts.

Available checks:
  - headers:   Missing/weak security headers (CSP, HSTS, X-Frame-Options, etc.)
  - cookies:   Secure/HttpOnly/SameSite flags
  - exposure:  Exposed files (.git/HEAD, .env, backups, .DS_Store, debug endpoints)
  - takeover:  Dangling CNAME + provider fingerprint matching
  - cors:      Permissive CORS (reflected origin with credentials)
  - tls:       Certificate issues (expired, soon-expiring, weak protocols)

All checks are passive/read-only. No exploitation or payload injection.
`,
	Example: `  scoutr scan --scope scope.yaml -i live.jsonl -o findings.jsonl
  scoutr scan --scope scope.yaml -i live.jsonl --checks headers,cookies -o findings.jsonl
  scoutr scan --scope scope.yaml -i live.jsonl --skip cors,tls -o findings.jsonl`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("input", "i", "", "Input file (JSONL format)")
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg := globalConfig

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}

	_, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	// Read input
	inputFile, _ := cmd.Flags().GetString("input")
	var input *os.File
	if inputFile != "" {
		input, err = os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("open input file: %w", err)
		}
		defer input.Close()
	} else {
		input = os.Stdin
	}

	// Open output
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

	// Parse input (JSONL)
	decoder := json.NewDecoder(input)
	var hosts []string
	for {
		var entry map[string]interface{}
		if err := decoder.Decode(&entry); err != nil {
			break
		}
		if h, ok := entry["host"].(string); ok {
			hosts = append(hosts, h)
		}
		if u, ok := entry["url"].(string); ok {
			hosts = append(hosts, u)
		}
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no hosts found in input")
	}

	// TODO: Run checks (Phase 4)
	fmt.Printf("Scanning %d hosts...\n", len(hosts))
	fmt.Fprintf(out, "# Scan results for %d hosts\n", len(hosts))
	fmt.Fprintf(out, "# Checks: %v\n", cfg.Checks)
	fmt.Fprintf(out, "# Skip: %v\n", cfg.SkipChecks)

	return nil
}
