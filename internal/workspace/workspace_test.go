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
