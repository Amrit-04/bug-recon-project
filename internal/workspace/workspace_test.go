package workspace

import (
	"os"
	"path/filepath"
	"strings"
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

func TestArtifactSaveLoadAndSafeName(t *testing.T) {
	ws, err := NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	for _, invalid := range []string{"", "../escaped.json", "..\\escaped.json", "/abs.json", "dir/sub.json", "..", "."} {
		if err := ws.SaveArtifact(invalid, map[string]string{"k": "v"}); err == nil {
			t.Errorf("SaveArtifact(%q) expected error", invalid)
		}
		var out map[string]string
		if err := ws.LoadArtifact(invalid, &out); err == nil {
			t.Errorf("LoadArtifact(%q) expected error", invalid)
		}
	}

	payload := map[string]string{"stage": "ports", "status": "ok"}
	if err := ws.SaveArtifact("ports.json", payload); err != nil {
		t.Fatalf("SaveArtifact: %v", err)
	}

	var loaded map[string]string
	if err := ws.LoadArtifact("ports.json", &loaded); err != nil {
		t.Fatalf("LoadArtifact: %v", err)
	}
	if loaded["stage"] != "ports" {
		t.Errorf("artifact payload mismatch: %v", loaded)
	}

	// Empty file handling
	emptyFile := filepath.Join(ws.Dir, "empty.json")
	if err := os.WriteFile(emptyFile, []byte("   "), 0644); err != nil {
		t.Fatal(err)
	}
	var emptyOut map[string]string
	if err := ws.LoadArtifact("empty.json", &emptyOut); err == nil {
		t.Fatal("expected error loading empty artifact")
	}
}

func TestListDrafts(t *testing.T) {
	ws, err := NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	// Nonexistent drafts dir
	drafts, err := ws.ListDrafts()
	if err != nil || len(drafts) != 0 {
		t.Fatalf("expected 0 drafts, got %v (err: %v)", drafts, err)
	}

	ws.SaveDraft("d1.md", "content1")
	ws.SaveDraft("d2.md", "content2")

	drafts, err = ws.ListDrafts()
	if err != nil {
		t.Fatalf("ListDrafts: %v", err)
	}
	if len(drafts) != 2 {
		t.Errorf("expected 2 drafts, got %d: %v", len(drafts), drafts)
	}
}

func TestLoadRawFindingsJSONLAndBOM(t *testing.T) {
	ws, err := NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	rawJSONL := `{"id":"raw-1","check_name":"test","target":"https://example.com","title":"Finding 1","severity":"high","confidence":"high"}
{"id":"raw-2","check_name":"test","target":"https://example.com","title":"Finding 2","severity":"low","confidence":"low"}`
	payload := append(append([]byte{}, utf8BOM...), []byte(rawJSONL)...)
	if err := os.WriteFile(filepath.Join(ws.Dir, RawFindingsFile), payload, 0644); err != nil {
		t.Fatal(err)
	}

	list, err := ws.LoadRawFindings()
	if err != nil {
		t.Fatalf("LoadRawFindings: %v", err)
	}
	if len(list) != 2 || list[0].ID != "raw-1" || list[1].ID != "raw-2" {
		t.Fatalf("unexpected findings: %+v", list)
	}

	// Invalid JSON format
	if err := os.WriteFile(filepath.Join(ws.Dir, RawFindingsFile), []byte("invalid-json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.LoadRawFindings(); err == nil {
		t.Fatal("expected error for invalid raw findings JSON")
	}
}

func TestLoadValidatedFindingsJSONL(t *testing.T) {
	ws, err := NewRun(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	vfJSONL := `{"finding":{"id":"vf-1","check_name":"c","target":"https://example.com","title":"t1"},"status":"Verified"}
{"finding":{"id":"vf-2","check_name":"c","target":"https://example.com","title":"t2"},"status":"NeedsManualReview"}`
	if err := os.WriteFile(filepath.Join(ws.Dir, ValidatedFindingsFile), []byte(vfJSONL), 0644); err != nil {
		t.Fatal(err)
	}

	list, err := ws.LoadValidatedFindings()
	if err != nil {
		t.Fatalf("LoadValidatedFindings: %v", err)
	}
	if len(list) != 2 || list[0].Finding.ID != "vf-1" || list[1].Finding.ID != "vf-2" {
		t.Fatalf("unexpected findings: %+v", list)
	}

	// Invalid JSON format
	if err := os.WriteFile(filepath.Join(ws.Dir, ValidatedFindingsFile), []byte("invalid-json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.LoadValidatedFindings(); err == nil {
		t.Fatal("expected error for invalid validated findings JSON")
	}
}

func TestSanitizeTarget(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://example.com", "example.com"},
		{"http://test.example.com:8080/path?q=1", "test.example.com_8080_path_q_1"},
		{"a" + strings.Repeat("b", 100), "a" + strings.Repeat("b", 49)},
	}
	for _, tc := range cases {
		got := SanitizeTarget(tc.input)
		if got != tc.want {
			t.Errorf("SanitizeTarget(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
