package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/recon/probe"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
)

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe hosts for live status, title, headers, and redirect chains",
	Long: `Probe a list of hosts to determine which are live and gather basic information.

For each host, probes:
  - HTTP/HTTPS status codes
  - Page title
  - Server header
  - Technology hints (from headers and HTML)
  - Redirect chain

Requests go through the scope-enforcing HTTP client, so --rate, --rate-per-host,
--timeout, --user-agent and --header apply to every probe.
`,
	Example: `  scoutr probe --scope scope.yaml -i subs.jsonl -o live.jsonl
  cat subs.jsonl | scoutr probe --scope scope.yaml -o live.jsonl`,
	RunE: runProbe,
}

func init() {
	probeCmd.Flags().StringP("input", "i", "", "Input file (JSONL format)")
}

func runProbe(cmd *cobra.Command, args []string) error {
	cfg := globalConfig

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}

	s, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	// Read input from file or stdin
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

	// Read hosts from input (JSONL format: {"host": "example.com"})
	decoder := json.NewDecoder(input)
	var hosts []string
	seen := make(map[string]bool)
	for {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			break
		}
		h, _ := entry["host"].(string)
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no hosts found in input")
	}

	// Drop out-of-scope hosts up front; the transport would block them anyway,
	// but probing them only produces noise.
	hosts = tools.FilterTargetsInScope(s, hosts)
	if len(hosts) == 0 {
		return fmt.Errorf("all input hosts were out of scope")
	}

	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s\n", cfg.ScopeFile)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would probe %d hosts: %v\n", len(hosts), hosts)
		return nil
	}

	results, err := probe.Hosts(cmd.Context(), s, hosts, probe.Options{
		Timeout:     cfg.Timeout,
		MaxBodySize: cfg.MaxBodyBytes,
		UserAgent:   cfg.UserAgent,
		Headers:     cfg.Headers,
		GlobalRate:  cfg.Rate,
		PerHostRate: cfg.RatePerHost,
	})
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}

	// Open output only once there is something to write.
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
	live := 0
	for _, result := range results {
		if result.Live {
			live++
		}
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Probed %d hosts, %d live\n", len(results), live)
	return nil
}
