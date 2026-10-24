package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
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

External Posture Verification (Opt-In):
  --verify-posture: Runs nuclei strictly in read-only observation mode with safe templates
  (tags: ssl,tls,tech,headers,misconfig,exposure; excluded: fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf).

All checks are passive/read-only. No exploitation or payload injection.
`,
	Example: `  scoutr scan --scope scope.yaml -i live.jsonl -o findings.jsonl
  scoutr scan --scope scope.yaml -i live.jsonl --verify-posture -o findings.jsonl
  scoutr scan --scope scope.yaml -i live.jsonl --checks headers,cookies -o findings.jsonl
  scoutr scan --scope scope.yaml -i live.jsonl --skip cors,tls -o findings.jsonl`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("input", "i", "", "Input file (JSONL format)")
	scanCmd.Flags().BoolVar(&globalConfig.VerifyPosture, "verify-posture", false,
		"Opt-in read-only posture auditing via nuclei with strictly safe observation tags")
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg := globalConfig

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}

	s, err := scope.LoadFromFile(cfg.ScopeFile)
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
	var targets []string
	seen := make(map[string]bool)
	for {
		var entry map[string]interface{}
		if err := decoder.Decode(&entry); err != nil {
			break
		}
		var t string
		if u, ok := entry["url"].(string); ok && u != "" {
			t = u
		} else if h, ok := entry["host"].(string); ok && h != "" {
			t = h
		}
		if t != "" && !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets found in input")
	}

	targets = tools.FilterTargetsInScope(s, targets)
	if len(targets) == 0 {
		return fmt.Errorf("all input targets were out of scope")
	}

	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s\n", cfg.ScopeFile)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would scan %d targets: %v\n", len(targets), targets)
		if cfg.VerifyPosture {
			fmt.Fprintf(os.Stderr, "[DRY-RUN] Would execute opt-in nuclei read-only posture check (-tags ssl,tls,tech,headers,misconfig,exposure -etags fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf)\n")
		}
		return nil
	}

	var allFindings []*findings.Finding
	runner := tools.NewExecRunner()
	logger := func(format string, args ...any) {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	// Opt-in external nuclei posture verification
	if cfg.VerifyPosture {
		logger("[INFO] Executing opt-in nuclei posture check (strictly read-only observation)...")
		nucFindings, err := tools.RunNucleiPosture(cmd.Context(), runner, s, targets, int(cfg.Rate), logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: nuclei posture check failed: %v\n", err)
		} else {
			allFindings = append(allFindings, nucFindings...)
		}
	}

	// Write findings as JSONL
	encoder := json.NewEncoder(out)
	for _, f := range allFindings {
		if err := encoder.Encode(f); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
	}

	fmt.Printf("Scan complete. Emitted %d findings\n", len(allFindings))
	return nil
}
