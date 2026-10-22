package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report from findings",
	Long: `Generate a formatted report from findings in JSONL format.

Supported formats:
  - jsonl: Raw JSONL (passthrough)
  - md:    Markdown report (HackerOne-style)
  - html:  Self-contained HTML report with light/dark mode support
`,
	Example: `  scoutr report -i findings.jsonl --format md -o report.md
  scoutr report -i findings.jsonl --format html -o report.html`,
	RunE: runReport,
}

func runReport(cmd *cobra.Command, args []string) error {
	cfg := globalConfig

	inputFile, _ := cmd.Flags().GetString("input")
	if inputFile == "" {
		return fmt.Errorf("--input is required")
	}

	// Open input
	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer input.Close()

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

	// TODO: Generate report (Phase 5)
	fmt.Fprintf(out, "# scoutr Report\n\n")
	fmt.Fprintf(out, "Input: %s\n", inputFile)
	fmt.Fprintf(out, "Format: %s\n", cfg.Format)
	fmt.Fprintf(out, "\n*Report generation not yet implemented (Phase 5)*\n")

	return nil
}

func init() {
	reportCmd.Flags().StringP("input", "i", "", "Input file (findings.jsonl)")
}
