package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/config"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/workspace"
)

func writeTestScope(t *testing.T, inScope []string, outScope []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	content := "in_scope:\n"
	for _, host := range inScope {
		content += "  - \"" + host + "\"\n"
	}
	content += "out_of_scope:\n"
	for _, host := range outScope {
		content += "  - \"" + host + "\"\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMergeUnique(t *testing.T) {
	initial := []string{"a", "b"}
	got := mergeUnique(initial, "b", "c", "", "  ", "d", "a")
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("mergeUnique length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAppendRawFindings(t *testing.T) {
	ws, err := workspace.NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	f1 := findings.NewFinding("F1", "check1", "https://example.com", "Title 1", findings.SeverityHigh, findings.ConfidenceHigh)
	f2 := findings.NewFinding("F2", "check2", "https://example.com", "Title 2", findings.SeverityLow, findings.ConfidenceLow)

	// First append adds 2
	added, err := appendRawFindings(ws, []*findings.Finding{f1, f2})
	if err != nil {
		t.Fatalf("appendRawFindings: %v", err)
	}
	if added != 2 {
		t.Errorf("expected 2 added, got %d", added)
	}

	// Second append with duplicates adds 0
	added, err = appendRawFindings(ws, []*findings.Finding{f1, f2})
	if err != nil {
		t.Fatalf("appendRawFindings duplicate: %v", err)
	}
	if added != 0 {
		t.Errorf("expected 0 added on duplicate, got %d", added)
	}

	// Append a new finding
	f3 := findings.NewFinding("F3", "check3", "https://example.com", "Title 3", findings.SeverityMedium, findings.ConfidenceMedium)
	added, err = appendRawFindings(ws, []*findings.Finding{f1, f3})
	if err != nil {
		t.Fatalf("appendRawFindings: %v", err)
	}
	if added != 1 {
		t.Errorf("expected 1 added, got %d", added)
	}
}

func TestReadTargetsFromInput(t *testing.T) {
	content := "example.com\n{\"host\":\"api.example.com\"}\n{\"url\":\"https://admin.example.com/test\"}\n\nexample.com\n"
	tmpFile := filepath.Join(t.TempDir(), "targets.jsonl")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	targets, err := readTargetsFromInput(tmpFile)
	if err != nil {
		t.Fatalf("readTargetsFromInput: %v", err)
	}
	want := []string{"example.com", "api.example.com", "https://admin.example.com/test"}
	if len(targets) != len(want) {
		t.Fatalf("targets length = %d, want %d: %v", len(targets), len(want), targets)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Errorf("targets[%d] = %q, want %q", i, targets[i], want[i])
		}
	}
}

func TestScopeTargetLabel(t *testing.T) {
	scopeFile := writeTestScope(t, []string{"sub.example.com", "test.example.com"}, nil)
	s, err := scope.LoadFromFile(scopeFile)
	if err != nil {
		t.Fatal(err)
	}
	label := scopeTargetLabel(s)
	if label != "sub.example.com" {
		t.Errorf("label = %q, want 'sub.example.com'", label)
	}

	emptyScope := &scope.Scope{}
	if scopeTargetLabel(emptyScope) != "scoutr-run" {
		t.Errorf("empty scope label = %q, want 'scoutr-run'", scopeTargetLabel(emptyScope))
	}
}

func TestDryRunCommands(t *testing.T) {
	scopeFile := writeTestScope(t, []string{"example.com", "*.example.com"}, []string{"admin.example.com"})

	// Save and restore global config
	oldCfg := globalConfig
	defer func() { globalConfig = oldCfg }()

	globalConfig = config.Defaults()
	globalConfig.ScopeFile = scopeFile
	globalConfig.DryRun = true

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	// Test enum dry-run
	if err := runEnum(cmd, nil); err != nil {
		t.Errorf("runEnum --dry-run failed: %v", err)
	}

	// Test urls dry-run
	if err := runURLs(cmd, nil); err != nil {
		t.Errorf("runURLs --dry-run failed: %v", err)
	}

	// Test crawl dry-run
	if err := runCrawl(cmd, nil); err != nil {
		t.Errorf("runCrawl --dry-run failed: %v", err)
	}

	// Test ports dry-run with input file
	targetsFile := filepath.Join(t.TempDir(), "hosts.jsonl")
	os.WriteFile(targetsFile, []byte("example.com\n"), 0644)
	portsInputFile = targetsFile
	defer func() { portsInputFile = "" }()
	if err := runPorts(cmd, nil); err != nil {
		t.Errorf("runPorts --dry-run failed: %v", err)
	}

	// Test fuzz dry-run with input file
	fuzzInputFile = targetsFile
	defer func() { fuzzInputFile = "" }()
	if err := runFuzz(cmd, nil); err != nil {
		t.Errorf("runFuzz --dry-run failed: %v", err)
	}

	// Test xss dry-run with parameterised URL
	urlsFile := filepath.Join(t.TempDir(), "urls.jsonl")
	os.WriteFile(urlsFile, []byte("https://example.com/search?q=test\n"), 0644)
	xssInputFile = urlsFile
	defer func() { xssInputFile = "" }()
	if err := runXSS(cmd, nil); err != nil {
		t.Errorf("runXSS --dry-run failed: %v", err)
	}
}

func TestValidateCommand(t *testing.T) {
	scopeFile := writeTestScope(t, []string{"example.com"}, []string{"out.example.com"})

	rawJSONL := `{"id":"f-in","check_name":"c","target":"https://example.com/login","title":"In scope","severity":"high","confidence":"high","rule_id":"missing-hsts-header","evidence":"hsts missing"}
{"id":"f-out","check_name":"c","target":"https://out.example.com/login","title":"Out of scope","severity":"high","confidence":"high","rule_id":"missing-hsts-header","evidence":"hsts missing"}`

	inputFile := filepath.Join(t.TempDir(), "raw.jsonl")
	outputFile := filepath.Join(t.TempDir(), "validated.jsonl")
	if err := os.WriteFile(inputFile, []byte(rawJSONL), 0644); err != nil {
		t.Fatal(err)
	}

	oldCfg := globalConfig
	defer func() { globalConfig = oldCfg }()

	globalConfig = config.Defaults()
	globalConfig.ScopeFile = scopeFile
	globalConfig.OutputFile = outputFile

	validateInput = inputFile
	defer func() { validateInput = "" }()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	if err := runValidate(cmd, nil); err != nil {
		t.Fatalf("runValidate: %v", err)
	}

	outData, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read validated output: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(outData)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 validated lines, got %d", len(lines))
	}

	// f-in should pass Gate 1 (scope), f-out should fail Gate 1 and be Suppressed
	if !strings.Contains(lines[0], `"status":"Verified"`) && !strings.Contains(lines[0], `"status":"NeedsManualReview"`) {
		t.Errorf("expected f-in to not be suppressed: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"status":"Suppressed"`) {
		t.Errorf("expected out-of-scope finding to be suppressed: %s", lines[1])
	}
}

func TestReportCommand(t *testing.T) {
	scopeFile := writeTestScope(t, []string{"example.com"}, nil)

	vfJSONL := `{"finding":{"id":"vf-1","check_name":"header-hsts-missing","target":"https://example.com/login","title":"Missing HSTS header","severity":"high","confidence":"high","rule_id":"missing-hsts-header","evidence":"hsts missing"},"status":"Verified"}`

	inputFile := filepath.Join(t.TempDir(), "validated.jsonl")
	outputMD := filepath.Join(t.TempDir(), "report.md")
	outputHTML := filepath.Join(t.TempDir(), "report.html")
	if err := os.WriteFile(inputFile, []byte(vfJSONL), 0644); err != nil {
		t.Fatal(err)
	}

	oldCfg := globalConfig
	defer func() { globalConfig = oldCfg }()

	reportInputFile = inputFile
	defer func() { reportInputFile = "" }()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	// Test Markdown report
	globalConfig = config.Defaults()
	globalConfig.ScopeFile = scopeFile
	globalConfig.OutputFile = outputMD
	globalConfig.Format = "md"
	if err := runReport(cmd, nil); err != nil {
		t.Fatalf("runReport md: %v", err)
	}
	mdBytes, err := os.ReadFile(outputMD)
	if err != nil || !bytes.Contains(mdBytes, []byte("Missing HSTS header")) {
		t.Fatalf("expected markdown report containing finding, got: %s", string(mdBytes))
	}

	// Test HTML report
	globalConfig.OutputFile = outputHTML
	globalConfig.Format = "html"
	if err := runReport(cmd, nil); err != nil {
		t.Fatalf("runReport html: %v", err)
	}
	htmlBytes, err := os.ReadFile(outputHTML)
	if err != nil || !bytes.Contains(htmlBytes, []byte("<!DOCTYPE html>")) {
		t.Fatalf("expected valid HTML report, got: %s", string(htmlBytes))
	}
}

func TestUICommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := &cobra.Command{}
	cmd.SetContext(ctx)

	// Save and restore flags
	oldPort, oldNoBrowser, oldHost := uiPort, uiNoBrowser, uiHost
	defer func() {
		uiPort, uiNoBrowser, uiHost = oldPort, oldNoBrowser, oldHost
	}()

	uiPort = 0 // random port
	uiHost = "127.0.0.1"
	uiNoBrowser = true

	// Cancel context immediately so runUI exits cleanly after starting
	cancel()

	err := runUI(cmd, nil)
	if err != nil {
		t.Fatalf("runUI: %v", err)
	}
}
