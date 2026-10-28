package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/workspace"
)

// readTargetsFromInput reads hosts/URLs from a JSONL file, accepting both
// {"host": "..."} and {"url": "..."} records plus bare lines. An empty path
// reads stdin.
func readTargetsFromInput(path string) ([]string, error) {
	var in *os.File
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open input file: %w", err)
		}
		defer f.Close()
		in = f
	} else {
		in = os.Stdin
	}

	var targets []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), tools.MaxScanLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var parsed map[string]string
		if err := json.Unmarshal([]byte(line), &parsed); err == nil {
			if u, ok := parsed["url"]; ok && u != "" {
				line = u
			} else if h, ok := parsed["host"]; ok && h != "" {
				line = h
			}
		}
		if !seen[line] {
			seen[line] = true
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return targets, nil
}

// appendRawFindings merges newly discovered findings into raw_findings.json,
// deduplicating on Finding.Key(). It returns the number of newly persisted
// findings.
func appendRawFindings(ws *workspace.Workspace, incoming []*findings.Finding) (int, error) {
	existing, err := ws.LoadRawFindings()
	if err != nil {
		existing = nil // no raw findings yet
	}

	seen := make(map[string]bool, len(existing))
	for _, f := range existing {
		seen[f.Key()] = true
	}

	added := 0
	for _, f := range incoming {
		if f == nil || seen[f.Key()] {
			continue
		}
		seen[f.Key()] = true
		existing = append(existing, f)
		added++
	}

	if added == 0 {
		return 0, nil
	}
	if err := ws.SaveRawFindings(existing); err != nil {
		return 0, err
	}
	return added, nil
}

// writeJSONL encodes values as one JSON object per line to the output file or
// stdout when path is empty.
func writeJSONL(path string, values []any) error {
	var out *os.File
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	} else {
		out = os.Stdout
	}

	encoder := json.NewEncoder(out)
	for _, v := range values {
		if err := encoder.Encode(v); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	return nil
}

// mergeUnique appends values that are not already present, preserving order.
func mergeUnique(existing []string, more ...string) []string {
	seen := make(map[string]bool, len(existing))
	for _, v := range existing {
		seen[v] = true
	}
	for _, v := range more {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		existing = append(existing, v)
	}
	return existing
}

// scopeTargetLabel derives a human-readable run label from the scope file.
func scopeTargetLabel(s *scope.Scope) string {
	domains := tools.ExtractRootDomains(s)
	if len(domains) > 0 {
		return domains[0]
	}
	return "scoutr-run"
}

// runHTTPXStage probes targets with the httpx binary after port data has been
// merged in, returning only in-scope live results.
func runHTTPXStage(ctx context.Context, s *scope.Scope, targets []string, rate int, log tools.LogFunc) ([]tools.HTTPXResult, error) {
	runner := tools.NewExecRunner()
	return tools.RunPDHTTPX(ctx, runner, s, targets, rate, log)
}

// loggerFor returns a stderr logger that honours --verbose.
func loggerFor(verbose bool) tools.LogFunc {
	return func(format string, args ...any) {
		if verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
}
