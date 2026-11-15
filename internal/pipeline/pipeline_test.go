package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/workspace"
)

func TestPipelineDryRun(t *testing.T) {
	sc := &scope.Scope{
		InScope: []string{"example.com", "*.example.com"},
	}

	stagesCalled := 0
	opts := Options{
		Scope:  sc,
		Target: "example.com",
		DryRun: true,
		OnProgress: func(stage int, stageName string, detail string) {
			stagesCalled++
		},
	}

	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run dry-run: %v", err)
	}
	if res == nil || res.Target != "example.com" {
		t.Errorf("unexpected dry-run result: %+v", res)
	}
	if stagesCalled != 8 {
		t.Errorf("expected 8 progress calls, got %d", stagesCalled)
	}
}

func TestPipelineRunWithMockRunner(t *testing.T) {
	tmpDir := t.TempDir()
	sc := &scope.Scope{
		InScope: []string{"api.example.com"},
	}

	mockRunner := tools.NewMockRunner()
	mockRunner.RegisterTool("dnsx", "/usr/bin/dnsx", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`{"host":"api.example.com","status":"NOERROR"}` + "\n"), nil, nil
	})
	mockRunner.RegisterTool("naabu", "/usr/bin/naabu", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`{"host":"api.example.com","ip":"192.0.2.1","port":443}` + "\n"), nil, nil
	})
	mockRunner.RegisterTool("httpx", "/usr/bin/httpx", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`{"url":"https://api.example.com:443","status_code":200,"title":"API"}` + "\n"), nil, nil
	})
	mockRunner.RegisterTool("katana", "/usr/bin/katana", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`{"request":{"endpoint":"https://api.example.com:443/v1"}}` + "\n"), nil, nil
	})
	mockRunner.RegisterTool("ffuf", "/usr/bin/ffuf", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`{"url":"https://api.example.com:443/admin","status":200,"length":50}` + "\n"), nil, nil
	})
	mockRunner.RegisterTool("dalfox", "/usr/bin/dalfox", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`[{"type":"V-XSS","param":"q","url":"https://api.example.com:443/search?q=1"}]`), nil, nil
	})
	mockRunner.RegisterTool("nuclei", "/usr/bin/nuclei", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`{"template-id":"ssl-issuer","info":{"name":"SSL Info","severity":"info"},"matched-at":"https://api.example.com:443"}` + "\n"), nil, nil
	})

	var progressStages []int
	opts := Options{
		Scope:       sc,
		Target:      "api.example.com",
		RunsDir:     filepath.Join(tmpDir, "runs"),
		SkipNmap:    true,
		PassiveOnly: true,
		Runner:      mockRunner,
		OnProgress: func(stage int, stageName string, detail string) {
			progressStages = append(progressStages, stage)
		},
	}

	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run pipeline: %v", err)
	}

	if res.Workspace == nil {
		t.Fatal("expected workspace run to be created")
	}

	// Verify artifacts were saved in run workspace
	inv, err := res.Workspace.LoadInventory()
	if err != nil || len(inv) == 0 {
		t.Errorf("inventory missing or empty: %v", err)
	}

	raw, err := res.Workspace.LoadRawFindings()
	if err != nil {
		t.Errorf("load raw findings: %v", err)
	}
	if len(raw) == 0 {
		t.Errorf("expected raw findings from dalfox/nuclei, got 0")
	}

	validated, err := res.Workspace.LoadValidatedFindings()
	if err != nil {
		t.Errorf("load validated findings: %v", err)
	}
	if len(validated) == 0 {
		t.Errorf("expected validated findings, got 0")
	}

	// Check report.md was generated
	reportMDPath := filepath.Join(res.Workspace.Dir, workspace.ReportMDFile)
	if _, err := os.Stat(reportMDPath); err != nil {
		t.Errorf("expected %s to be created: %v", reportMDPath, err)
	}
}

func TestPipelineModularRunners(t *testing.T) {
	tmpDir := t.TempDir()
	ws, err := workspace.NewRun(tmpDir, "example.com")
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	sc := &scope.Scope{InScope: []string{"api.example.com"}}

	mockRunner := tools.NewMockRunner()

	// 1. RunSubdomainsOnly
	subs, err := RunSubdomainsOnly(context.Background(), ws, sc, mockRunner, false, true, 5, nil)
	if err != nil {
		t.Fatalf("RunSubdomainsOnly: %v", err)
	}
	if len(subs) == 0 {
		t.Errorf("expected subdomains, got 0")
	}

	// 2. ValidateOnly with a raw finding
	f := findings.NewFinding("F1", "test-check", "https://api.example.com", "Title", findings.SeverityLow, findings.ConfidenceHigh)
	_ = ws.SaveRawFindings([]*findings.Finding{f})

	val, err := RunValidateOnly(context.Background(), ws, sc)
	if err != nil {
		t.Fatalf("RunValidateOnly: %v", err)
	}
	if len(val) != 1 {
		t.Errorf("expected 1 validated finding, got %d", len(val))
	}
}

func TestMergeUniqueAndServiceFingerprints(t *testing.T) {
	merged := MergeUnique([]string{"a", "b"}, "b", "c", "", "d", "a")
	if len(merged) != 4 || merged[0] != "a" || merged[3] != "d" {
		t.Errorf("unexpected MergeUnique: %v", merged)
	}

	ports := []tools.PortResult{
		{Host: "api.example.com", Port: 80},
		{Host: "api.example.com", Port: 443},
	}
	services := []tools.PortResult{
		{Host: "api.example.com", Port: 443, Service: "https", Version: "1.2.3"},
		{Host: "unknown.example.com", Port: 22, Service: "ssh"},
	}

	res := MergeServiceFingerprints(ports, services)
	if len(res) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(res))
	}
	if res[1].Service != "https" || res[1].Version != "1.2.3" {
		t.Errorf("unexpected merged service: %+v", res[1])
	}
}
