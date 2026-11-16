package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/workspace"
)

func TestRCECLICommands(t *testing.T) {
	runDir := t.TempDir()
	ws, err := workspace.OpenRun(runDir)
	if err != nil {
		t.Fatalf("open workspace: %v", err)
	}
	ws.Target = "example.com"
	// Write scope file
	scopePath := filepath.Join(runDir, "scope.yaml")
	scopeContent := "in_scope:\n  - \"example.com\"\n  - \"*.example.com\"\nout_of_scope: []\n"
	if err := os.WriteFile(scopePath, []byte(scopeContent), 0644); err != nil {
		t.Fatalf("write scope: %v", err)
	}
	globalConfig.ScopeFile = scopePath
	defer func() { globalConfig.ScopeFile = "" }()

	// 1. Write mock endpoints.json
	endpointList := []*endpoints.Endpoint{
		{
			Origin:           "https://example.com",
			URL:              "https://example.com/api/v1/diag/ping",
			NormalizedRoute:  "/api/v1/diag/ping",
			Methods:          []string{"POST"},
			QueryParams:      []string{"target"},
			BodyFields:       []string{"host", "args"},
			TechFingerprints: []string{"Linux"},
		},
		{
			Origin:          "https://example.com",
			URL:             "https://example.com/api/v1/upload/doc",
			NormalizedRoute: "/api/v1/upload/doc",
			Methods:         []string{"POST"},
			ContentTypes:    []string{"multipart/form-data"},
			BodyFields:      []string{"file", "doc_id"},
		},
	}
	epData, _ := json.MarshalIndent(endpointList, "", "  ")
	if err := os.WriteFile(filepath.Join(runDir, workspace.EndpointsFile), epData, 0644); err != nil {
		t.Fatalf("write endpoints.json: %v", err)
	}

	// Test Command 1: scoutr rce discover
	rceFromDir = runDir
	if err := rceDiscoverCmd.RunE(rceDiscoverCmd, []string{}); err != nil {
		t.Fatalf("rce discover failed: %v", err)
	}

	// Verify rce_candidates.json was created
	candsPath := filepath.Join(runDir, workspace.RCECandidatesFile)
	if _, err := os.Stat(candsPath); err != nil {
		t.Fatalf("expected rce_candidates.json to exist: %v", err)
	}

	// Test Command 2: scoutr rce list
	if err := rceListCmd.RunE(rceListCmd, []string{}); err != nil {
		t.Fatalf("rce list failed: %v", err)
	}

	// Test Command 3: scoutr rce validate (passive profile)
	rceCandidateID = "rce_comm_api_v1_diag_ping_POST"
	rceProfileName = "passive"
	if err := rceValidateCmd.RunE(rceValidateCmd, []string{}); err != nil {
		t.Fatalf("rce validate failed: %v", err)
	}

	// Test Command 4: scoutr rce report
	reportPath := filepath.Join(runDir, "test_rce_report.md")
	rceOutputFile = reportPath
	if err := rceReportCmd.RunE(rceReportCmd, []string{}); err != nil {
		t.Fatalf("rce report failed: %v", err)
	}

	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(reportData), "Scoutr RCE Research and Attack Surface Report") {
		t.Errorf("expected report title in output")
	}
}

func init() {
	// Silence cobra output during unit tests
	RootCmd.SetOut(new(bytes.Buffer))
	RootCmd.SetErr(new(bytes.Buffer))
}
