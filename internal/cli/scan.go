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
	Short: "Run the opt-in read-only nuclei posture check",
	Long: `Run read-only posture verification against a list of live hosts.

Posture Verification (Opt-In, Required):
  --verify-posture: Runs nuclei strictly in read-only observation mode with safe templates
  (tags: ssl,tls,tech,headers,misconfig,exposure; excluded: fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf).

No built-in checks are compiled into this build, so "scoutr scan" requires
--verify-posture and otherwise refuses to run rather than reporting a scan that
inspected nothing. Local header/cookie/exposure/takeover/CORS/TLS checks are a
future milestone; until then "run" pipelines posture verification only.

All checks are passive/read-only. No exploitation or payload injection.
`,
	Example: `  scoutr scan --scope scope.yaml -i live.jsonl --verify-posture -o findings.jsonl`,
	RunE:    runScan,
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

	// Honesty guard: `scan` has no built-in checks in this build, so without
	// the opt-in nuclei posture stage it would inspect nothing and print a
	// clean result. Refuse instead.
	if err := scanPrecondition(cfg.VerifyPosture); err != nil {
		return err
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
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would execute opt-in nuclei read-only posture check (-tags ssl,tls,tech,headers,misconfig,exposure -etags fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf)\n")
		return nil
	}

	var allFindings []*findings.Finding
	runner := tools.NewExecRunner()
	logger := func(format string, args ...any) {
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	// Opt-in external nuclei posture verification. The guard above guarantees
	// this is the only engine that can run, and it only ever emits nuclei
	// posture findings.
	logger("[INFO] Executing opt-in nuclei posture check (strictly read-only observation)...")
	nucFindings, err := tools.RunNucleiPosture(cmd.Context(), runner, s, targets, int(cfg.Rate), logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: nuclei posture check failed: %v\n", err)
	} else {
		allFindings = append(allFindings, nucFindings...)
	}

	// Write findings as JSONL
	encoder := json.NewEncoder(out)
	for _, f := range allFindings {
		if err := encoder.Encode(f); err != nil {
			return fmt.Errorf("write finding: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Scan complete. Emitted %d findings\n", len(allFindings))
	return nil
}

// scanPrecondition explains why a scan that inspects nothing must not run: an
// empty result is indistinguishable from a clean scan. Until built-in checks
// exist, nuclei posture verification is the only engine scan has.
func scanPrecondition(verifyPosture bool) error {
	if verifyPosture {
		return nil
	}
	return fmt.Errorf("scan has no built-in checks in this build; pass --verify-posture to run the opt-in read-only nuclei posture check")
}
