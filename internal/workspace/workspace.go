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

	// Tier 1 stage artifacts produced by ports, crawl, fuzz and XSS stages.
	PortsFile = "ports.json"
	HTTPXFile = "httpx.json"
	CrawlFile = "crawl.json"
	FuzzFile  = "fuzz.json"

	// Tier 2 artifacts. triage.json NEVER feeds the report directly: it only
	// influences ordering, while validated_findings.json stays the source of truth.
	TriageFile = "triage.json"

	// Tier 3 (human) artifacts.
	DraftsDir           = "reports/drafts"
	DraftIndexFile      = "index.md"
	SubmissionQueueFile = "submission_ready.json"
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

	// Files written by other tooling (notably PowerShell's ``-Encoding utf8``)
	// may start with a UTF-8 BOM, which JSON decoders reject.
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
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

// utf8BOM is prepended by some Windows editors (PowerShell's Set-Content
// -Encoding utf8, Notepad) and would otherwise defeat the JSON array/JSONL
// format detection below.
var utf8BOM = []byte("\xef\xbb\xbf")

// LoadRawFindings reads raw findings from raw_findings.json (supporting both JSON array and JSONL).
func (w *Workspace) LoadRawFindings() ([]*findings.Finding, error) {
	path := filepath.Join(w.Dir, RawFindingsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read raw findings: %w", err)
	}

	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
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

	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
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

// safeArtifactName rejects any artifact name that could escape the run directory.
func safeArtifactName(name string) error {
	if name == "" {
		return fmt.Errorf("artifact name is required")
	}
	if filepath.IsAbs(name) || strings.ContainsAny(name, `\/`) || name == ".." || name == "." {
		return fmt.Errorf("invalid artifact name %q: must be a plain file name inside the run directory", name)
	}
	return nil
}

// SaveArtifact marshals v as indented JSON into <runDir>/<name>.
// It is used for stage artifacts (ports, httpx, crawl, fuzz, triage).
func (w *Workspace) SaveArtifact(name string, v any) error {
	if err := safeArtifactName(name); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal artifact %s: %w", name, err)
	}
	return os.WriteFile(filepath.Join(w.Dir, name), data, 0644)
}

// LoadArtifact unmarshals <runDir>/<name> into v.
func (w *Workspace) LoadArtifact(name string, v any) error {
	if err := safeArtifactName(name); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(w.Dir, name))
	if err != nil {
		return fmt.Errorf("read artifact %s: %w", name, err)
	}
	data = bytes.TrimSpace(bytes.TrimPrefix(data, utf8BOM))
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("artifact %s is empty", name)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("unmarshal artifact %s: %w", name, err)
	}
	return nil
}

// DraftDir returns the absolute path of the draft directory (reports/drafts).
func (w *Workspace) DraftDir() string {
	return filepath.Join(w.Dir, filepath.FromSlash(DraftsDir))
}

// DraftPath resolves a draft file name inside reports/drafts and refuses any
// name that would escape that directory.
func (w *Workspace) DraftPath(fileName string) (string, error) {
	if err := safeArtifactName(fileName); err != nil {
		return "", err
	}
	dir := w.DraftDir()
	path := filepath.Join(dir, fileName)
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("draft path %q escapes %s", fileName, dir)
	}
	return path, nil
}

// SaveDraft writes a Markdown draft to reports/drafts/<fileName> and returns
// its absolute path. Drafts are deliberately kept out of any submission-ready
// location: a human must pass scoutr submit --require-approval first.
func (w *Workspace) SaveDraft(fileName, content string) (string, error) {
	path, err := w.DraftPath(fileName)
	if err != nil {
		return "", err
	}
	dir := w.DraftDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create draft directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("write draft %s: %w", fileName, err)
	}
	return path, nil
}

// ListDrafts returns the plain file names of all drafts in reports/drafts.
func (w *Workspace) ListDrafts() ([]string, error) {
	entries, err := os.ReadDir(w.DraftDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list drafts: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}
