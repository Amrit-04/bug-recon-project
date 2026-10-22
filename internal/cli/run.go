package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the full pipeline: enum → probe → scan → report",
	Long: `Run the complete scoutr pipeline in sequence:
  1. Enumerate subdomains (passive + optional brute force)
  2. Probe hosts for live status
  3. Scan live hosts with security checks
  4. Generate a report

This is equivalent to running enum, probe, scan, and report sequentially,
but with automatic piping of results between stages.
`,
	Example: `  scoutr run --scope scope.yaml
  scoutr run --scope scope.yaml --brute --checks headers,cookies
  scoutr run --scope scope.yaml --format html -o report.html`,
	RunE: runPipeline,
}

func runPipeline(cmd *cobra.Command, args []string) error {
	// TODO: Implement full pipeline (Phase 5)
	fmt.Println("Full pipeline not yet implemented (Phase 5)")
	fmt.Println("For now, run each stage separately:")
	fmt.Println("  scoutr enum --scope scope.yaml -o subs.jsonl")
	fmt.Println("  scoutr probe --scope scope.yaml -i subs.jsonl -o live.jsonl")
	fmt.Println("  scoutr scan --scope scope.yaml -i live.jsonl -o findings.jsonl")
	fmt.Println("  scoutr report -i findings.jsonl --format md -o report.md")
	return nil
}
