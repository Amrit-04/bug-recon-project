package workspace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

// Standard artifact file names within a run directory
const (
	InventoryFile         = "inventory.json"
	RawFindingsFile       = "raw_findings.json"
	ValidatedFindingsFile = "validated_findings.json"
	ReportMDFile          = "report.md"
	ReportHTMLFile        = "report.html"
)

// Workspace manages persistence of recon and scan artifacts for an audit session.
type Workspace struct {
	Dir    string `json:"dir"`
	Target string `json:"target"`
}

// sanitizeTarget cleans target domain/URL for safe directory naming on Windows/Linux.
var sanitizeRegex = regexp.MustCompile(`[^a-zA-Z0-9_\-\.]`)

func SanitizeTarget(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = sanitizeRegex.ReplaceAllString(target, "_")
	if len(target) > 50 {
		target = target[:50]
	}
	return target
}

// NewRun creates a new timestamped workspace directory under baseDir (default ".scoutr/runs").
func NewRun(baseDir, target string) (*Workspace, error) {
	if baseDir == "" {
		baseDir = filepath.Join(".scoutr", "runs")
	}

	sanitized := SanitizeTarget(target)
	timestamp := time.Now().Format("20060102-150405")
	runDirName := fmt.Sprintf("%s-%s", sanitized, timestamp)
	runDirPath := filepath.Join(baseDir, runDirName)

	if err := os.MkdirAll(runDirPath, 0755); err != nil {
		return nil, fmt.Errorf("create run directory: %w", err)
	}

	return &Workspace{
		Dir:    runDirPath,
		Target: target,
	}, nil
}

// OpenRun opens an existing run directory.
func OpenRun(runDir string) (*Workspace, error) {
	info, err := os.Stat(runDir)
	if err != nil {
		return nil, fmt.Errorf("stat run directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", runDir)
	}

	return &Workspace{
		Dir: runDir,
	}, nil
}

// SaveInventory writes in-scope inventory targets to inventory.json.
func (w *Workspace) SaveInventory(targets []string) error {
	path := filepath.Join(w.Dir, InventoryFile)
	data, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadInventory reads targets from inventory.json (supporting both JSON array and JSONL).
func (w *Workspace) LoadInventory() ([]string, error) {
	path := filepath.Join(w.Dir, InventoryFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if trimmed[0] == '[' {
		var targets []string
		if err := json.Unmarshal(trimmed, &targets); err == nil {
			return targets, nil
		}
	}

	var targets []string
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var parsed map[string]string
		if err := json.Unmarshal([]byte(line), &parsed); err == nil {
			if h, ok := parsed["host"]; ok && h != "" {
				targets = append(targets, h)
				continue
			}
			if u, ok := parsed["url"]; ok && u != "" {
				targets = append(targets, u)
				continue
			}
		}
		targets = append(targets, line)
	}
	return targets, nil
}

// SaveRawFindings saves raw findings before validation.
func (w *Workspace) SaveRawFindings(raw []*findings.Finding) error {
	path := filepath.Join(w.Dir, RawFindingsFile)
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal raw findings: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadRawFindings reads raw findings from raw_findings.json (supporting both JSON array and JSONL).
func (w *Workspace) LoadRawFindings() ([]*findings.Finding, error) {
	path := filepath.Join(w.Dir, RawFindingsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read raw findings: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if trimmed[0] == '[' {
		var list []*findings.Finding
		if err := json.Unmarshal(trimmed, &list); err == nil {
			return list, nil
		}
	}

	var list []*findings.Finding
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var f findings.Finding
		if err := json.Unmarshal(line, &f); err == nil && f.ID != "" {
			list = append(list, &f)
		}
	}
	if len(list) > 0 {
		return list, nil
	}

	return nil, fmt.Errorf("unmarshal raw findings: invalid JSON format")
}

// SaveValidatedFindings saves findings filtered and grouped by the validation gate.
func (w *Workspace) SaveValidatedFindings(vf []*validate.ValidatedFinding) error {
	path := filepath.Join(w.Dir, ValidatedFindingsFile)
	data, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal validated findings: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadValidatedFindings loads validated findings from validated_findings.json (supporting both JSON array and JSONL).
func (w *Workspace) LoadValidatedFindings() ([]*validate.ValidatedFinding, error) {
	path := filepath.Join(w.Dir, ValidatedFindingsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read validated findings: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}

	if trimmed[0] == '[' {
		var list []*validate.ValidatedFinding
		if err := json.Unmarshal(trimmed, &list); err == nil {
			return list, nil
		}
	}

	var list []*validate.ValidatedFinding
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var vf validate.ValidatedFinding
		if err := json.Unmarshal(line, &vf); err == nil && vf.Finding != nil {
			list = append(list, &vf)
		}
	}
	if len(list) > 0 {
		return list, nil
	}

	return nil, fmt.Errorf("unmarshal validated findings: invalid JSON format")
}

// SaveReportMD writes Markdown report to report.md.
func (w *Workspace) SaveReportMD(content string) error {
	path := filepath.Join(w.Dir, ReportMDFile)
	return os.WriteFile(path, []byte(content), 0644)
}

// SaveReportHTML writes self-contained HTML report to report.html.
func (w *Workspace) SaveReportHTML(content string) error {
	path := filepath.Join(w.Dir, ReportHTMLFile)
	return os.WriteFile(path, []byte(content), 0644)
}
