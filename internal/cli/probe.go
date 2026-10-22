package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/recon/probe"
	"github.com/scoutr/scoutr/internal/scope"
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

	// Read hosts from input (JSONL format: {"host": "example.com"})
	decoder := json.NewDecoder(input)
	var hosts []string
	for {
		var entry map[string]string
		if err := decoder.Decode(&entry); err != nil {
			break
		}
		if h, ok := entry["host"]; ok {
			hosts = append(hosts, h)
		}
	}

	if len(hosts) == 0 {
		return fmt.Errorf("no hosts found in input")
	}

	// Probe each host
	encoder := json.NewEncoder(out)
	live := 0
	for _, host := range hosts {
		result, err := probe.Host(ctx, s, host)
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "probe %s: %v\n", host, err)
			}
			continue
		}
		if result.Live {
			live++
		}
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}

	fmt.Printf("Probed %d hosts, %d live\n", len(hosts), live)
	return nil
}
