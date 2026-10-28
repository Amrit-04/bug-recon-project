package workspace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/validate"
)

func TestWorkspaceLifecycle(t *testing.T) {
	tempBase, err := os.MkdirTemp("", "scoutr-ws-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempBase)

	ws, err := NewRun(tempBase, "example.com")
	if err != nil {
		t.Fatalf("failed to create run workspace: %v", err)
	}

	// 1. Inventory
	targets := []string{"api.example.com", "app.example.com"}
	if err := ws.SaveInventory(targets); err != nil {
		t.Fatalf("failed to save inventory: %v", err)
	}
	loadedTargets, err := ws.LoadInventory()
	if err != nil {
		t.Fatalf("failed to load inventory: %v", err)
	}
	if len(loadedTargets) != 2 || loadedTargets[0] != "api.example.com" {
		t.Errorf("inventory mismatch: %v", loadedTargets)
	}

	// 2. Raw findings
	f := findings.NewFinding("TEST-1", "test", "api.example.com", "Test Finding", findings.SeverityLow, findings.ConfidenceMedium)
	if err := ws.SaveRawFindings([]*findings.Finding{f}); err != nil {
		t.Fatalf("failed to save raw findings: %v", err)
	}
	loadedRaw, err := ws.LoadRawFindings()
	if err != nil {
		t.Fatalf("failed to load raw findings: %v", err)
	}
	if len(loadedRaw) != 1 || loadedRaw[0].Title != "Test Finding" {
		t.Errorf("raw findings mismatch: %v", loadedRaw)
	}

	// 3. Validated findings
	vf := &validate.ValidatedFinding{
		Finding: f,
		Status:  validate.StatusVerified,
	}
	if err := ws.SaveValidatedFindings([]*validate.ValidatedFinding{vf}); err != nil {
		t.Fatalf("failed to save validated findings: %v", err)
	}
	loadedVF, err := ws.LoadValidatedFindings()
	if err != nil {
		t.Fatalf("failed to load validated findings: %v", err)
	}
	if len(loadedVF) != 1 || loadedVF[0].Status != validate.StatusVerified {
		t.Errorf("validated findings mismatch: %v", loadedVF)
	}

	// 4. Reports
	mdReport := "# Test Report\nEverything looks good."
	htmlReport := "<html><body><h1>Report</h1></body></html>"
	if err := ws.SaveReportMD(mdReport); err != nil {
		t.Fatalf("failed to save report.md: %v", err)
	}
	if err := ws.SaveReportHTML(htmlReport); err != nil {
		t.Fatalf("failed to save report.html: %v", err)
	}

	// Verify files exist in directory
	for _, fname := range []string{InventoryFile, RawFindingsFile, ValidatedFindingsFile, ReportMDFile, ReportHTMLFile} {
		p := filepath.Join(ws.Dir, fname)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file %s to exist: %v", fname, err)
		}
	}

	// 5. OpenRun
	wsReopened, err := OpenRun(ws.Dir)
	if err != nil {
		t.Fatalf("failed to reopen workspace: %v", err)
	}
	reloadedTargets, err := wsReopened.LoadInventory()
	if err != nil || len(reloadedTargets) != 2 {
		t.Errorf("reopened workspace failed to load inventory: %v", err)
	}
}

// A UTF-8 BOM (written by PowerShell's Set-Content -Encoding utf8 on Windows)
// must not defeat the array/JSONL format detection.
func TestLoadValidatedFindingsWithBOM(t *testing.T) {
	ws, err := NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	body := `[{"finding":{"id":"bom-1","check_name":"c","target":"https://example.com","title":"t"},"status":"Verified"}]`
	payload := append(append([]byte{}, utf8BOM...), body...)
	if err := os.WriteFile(filepath.Join(ws.Dir, ValidatedFindingsFile), payload, 0644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	list, err := ws.LoadValidatedFindings()
	if err != nil {
		t.Fatalf("load validated findings: %v", err)
	}
	if len(list) != 1 || list[0].Finding.ID != "bom-1" {
		t.Fatalf("unexpected findings: %+v", list)
	}
}

// inventory.json can be produced by external tooling too, so it must tolerate
// a UTF-8 BOM in both the JSON-array and JSONL layouts.
func TestLoadInventoryWithBOM(t *testing.T) {
	ws, err := NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	cases := map[string][]string{
		`["api.example.com","www.example.com"]`:                                 {"api.example.com", "www.example.com"},
		"{\"host\":\"api.example.com\"}\n{\"url\":\"https://www.example.com\"}": {"api.example.com", "https://www.example.com"},
	}
	for body, want := range cases {
		payload := append(append([]byte{}, utf8BOM...), body...)
		if err := os.WriteFile(filepath.Join(ws.Dir, InventoryFile), payload, 0644); err != nil {
			t.Fatalf("write inventory: %v", err)
		}
		got, err := ws.LoadInventory()
		if err != nil {
			t.Fatalf("load inventory from %q: %v", body, err)
		}
		if len(got) != len(want) {
			t.Fatalf("LoadInventory(%q) = %v, want %v", body, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("LoadInventory(%q)[%d] = %q, want %q", body, i, got[i], want[i])
			}
		}
	}
}

// Drafts are confined to reports/drafts; traversal attempts are refused.
func TestDraftPathRejectsTraversal(t *testing.T) {
	ws, err := NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	for _, name := range []string{"../escape.md", "..\\escape.md", string(filepath.Separator) + "abs.md", ".."} {
		if _, err := ws.DraftPath(name); err == nil {
			t.Errorf("DraftPath(%q) should be refused", name)
		}
		if _, err := ws.SaveDraft(name, "x"); err == nil {
			t.Errorf("SaveDraft(%q) should be refused", name)
		}
	}

	path, err := ws.SaveDraft("ok.md", "# ok")
	if err != nil {
		t.Fatalf("SaveDraft(ok.md): %v", err)
	}
	if filepath.Dir(path) != ws.DraftDir() {
		t.Errorf("draft written outside %s: %s", ws.DraftDir(), path)
	}
}
