package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/report"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	reportFromRun   string
	reportInputFile string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate structured Markdown or self-contained HTML audit reports",
	Long: `Generate formatted, executive-ready reports from validated findings.

Supported formats:
  - md:    HackerOne/Bugcrowd structured Markdown report
  - html:  Self-contained interactive HTML report with light/dark theme toggle
  - jsonl: Raw stream output

Supports generating reports directly from workspace runs without re-scanning.
`,
	Example: `  scoutr report -i validated.jsonl --format md -o report.md
  scoutr report -i validated.jsonl --format html -o report.html
  scoutr report --from .scoutr/runs/example.com-20261024-120000 --format html`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportFromRun, "from", "", "Generate report from existing workspace run directory")
	reportCmd.Flags().StringVarP(&reportInputFile, "input", "i", "", "Input findings file (JSONL format)")
}

func runReport(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	format := strings.ToLower(cfg.Format)
	if format == "" {
		format = "md"
	}

	var validatedList []*validate.ValidatedFinding
	var ws *workspace.Workspace
	var targetName = "Target"

	// 1. Load from workspace run
	if reportFromRun != "" {
		var err error
		ws, err = workspace.OpenRun(reportFromRun)
		if err != nil {
			return fmt.Errorf("open workspace: %w", err)
		}

		// Try loading validated findings first
		validatedList, err = ws.LoadValidatedFindings()
		if err != nil || len(validatedList) == 0 {
			// Fallback: load raw findings and validate on the fly
			raw, loadErr := ws.LoadRawFindings()
			if loadErr != nil {
				return fmt.Errorf("load findings from workspace %s: %w", reportFromRun, loadErr)
			}
			validator := validate.NewValidator(nil)
			validatedList = validator.ValidateAndGroup(context.Background(), raw)
		}

		targetName = filepath.Base(ws.Dir)
		if idx := strings.LastIndex(targetName, "-"); idx != -1 {
			targetName = targetName[:idx]
		}
	} else {
		// 2. Load from input file or stdin
		if reportInputFile == "" {
			return fmt.Errorf("either --from <run-dir> or --input <file> is required")
		}

		in, err := os.Open(reportInputFile)
		if err != nil {
			return fmt.Errorf("open input file: %w", err)
		}
		defer in.Close()

		scanner := bufio.NewScanner(in)
		var rawList []*findings.Finding
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// Try unmarshaling as ValidatedFinding first
			var vf validate.ValidatedFinding
			if err := json.Unmarshal([]byte(line), &vf); err == nil && vf.Finding != nil && vf.Status != "" {
				validatedList = append(validatedList, &vf)
				if vf.Finding.Target != "" && targetName == "Target" {
					targetName = vf.Finding.Target
				}
				continue
			}

			// Fallback: unmarshal as raw Finding
			var f findings.Finding
			if err := json.Unmarshal([]byte(line), &f); err == nil && f.ID != "" {
				rawList = append(rawList, &f)
				if f.Target != "" && targetName == "Target" {
					targetName = f.Target
				}
			}
		}

		if len(validatedList) == 0 && len(rawList) > 0 {
			validator := validate.NewValidator(nil)
			validatedList = validator.ValidateAndGroup(context.Background(), rawList)
		}
	}

	if len(validatedList) == 0 {
		return fmt.Errorf("no findings to report")
	}

	// Generate report content according to format
	var reportContent string
	switch format {
	case "md", "markdown":
		reportContent = report.GenerateMarkdown(targetName, validatedList)
	case "html":
		reportContent = report.GenerateHTML(targetName, validatedList)
	case "jsonl", "json":
		var b strings.Builder
		encoder := json.NewEncoder(&b)
		for _, vf := range validatedList {
			_ = encoder.Encode(vf)
		}
		reportContent = b.String()
	default:
		return fmt.Errorf("unsupported report format %q (supported: md, html, jsonl)", format)
	}

	// Save to workspace if active
	if ws != nil {
		if format == "html" {
			_ = ws.SaveReportHTML(reportContent)
			fmt.Printf("Saved HTML report to: %s/%s\n", ws.Dir, workspace.ReportHTMLFile)
		} else {
			_ = ws.SaveReportMD(reportContent)
			fmt.Printf("Saved Markdown report to: %s/%s\n", ws.Dir, workspace.ReportMDFile)
		}
	}

	// Write to output file or stdout
	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, []byte(reportContent), 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		fmt.Printf("Report successfully written to %s\n", cfg.OutputFile)
	} else if ws == nil {
		var out io.Writer = os.Stdout
		fmt.Fprint(out, reportContent)
	}

	return nil
}
