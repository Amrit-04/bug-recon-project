package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/idor"
	"github.com/scoutr/scoutr/internal/workspace"
)

func TestIDORCLICommands(t *testing.T) {
	// Setup mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if r.URL.Path == "/api/docs/100" {
			if authHeader == "Bearer token_owner" || authHeader == "Bearer token_tester" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"id": 100, "content": "secret document", "owner": "owner"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	runDir := t.TempDir()
	ws, err := workspace.OpenRun(runDir)
	if err != nil {
		t.Fatalf("open workspace: %v", err)
	}

	// 1. Write endpoints.json into run directory
	endpointList := []*endpoints.Endpoint{
		{
			Origin:          server.URL,
			URL:             server.URL + "/api/docs/100",
			NormalizedRoute: "/api/docs/{id}",
			Methods:         []string{"GET"},
			ObservedObjects: []endpoints.ObjectIDCandidate{
				{Type: "path", Name: "doc_id", Value: "100", Kind: "integer"},
			},
			AuthObservations: []endpoints.AuthObservation{
				{Status: endpoints.AuthStatusAuthenticated, PrincipalLabel: "owner", TenantLabel: "tenant_1"},
			},
		},
	}
	epData, _ := json.MarshalIndent(endpointList, "", "  ")
	if err := os.WriteFile(filepath.Join(runDir, workspace.EndpointsFile), epData, 0644); err != nil {
		t.Fatalf("write endpoints.json: %v", err)
	}

	// 2. Write auth_profiles.json
	profiles := []*auth.Profile{
		{
			PrincipalLabel: "owner",
			TenantLabel:    "tenant_1",
			AuthType:       "bearer",
			Headers:        map[string]string{"Authorization": "Bearer token_owner"},
		},
		{
			PrincipalLabel: "tester",
			TenantLabel:    "tenant_2",
			AuthType:       "bearer",
			Headers:        map[string]string{"Authorization": "Bearer token_tester"},
		},
	}
	if err := auth.SaveProfiles(filepath.Join(runDir, "auth_profiles.json"), profiles); err != nil {
		t.Fatalf("save auth profiles: %v", err)
	}

	// Write scope file
	scopePath := filepath.Join(runDir, "scope.yaml")
	scopeContent := "in_scope:\n  - \"127.0.0.1\"\n  - \"localhost\"\nout_of_scope: []\n"
	if err := os.WriteFile(scopePath, []byte(scopeContent), 0644); err != nil {
		t.Fatalf("write scope: %v", err)
	}
	globalConfig.ScopeFile = scopePath

	// 3. Test `scoutr idor inventory --from <runDir>`
	RootCmd.SetArgs([]string{"idor", "inventory", "--from", runDir})
	var invBuf bytes.Buffer
	RootCmd.SetOut(&invBuf)
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("idor inventory failed: %v", err)
	}

	objectsFile := filepath.Join(runDir, workspace.IDORObjectsFile)
	if _, err := os.Stat(objectsFile); os.IsNotExist(err) {
		t.Fatalf("idor_objects.json not created")
	}

	// 4. Test `scoutr idor compare --from <runDir> --user-a owner --user-b tester`
	RootCmd.SetArgs([]string{"idor", "compare", "--from", runDir, "--user-a", "owner", "--user-b", "tester"})
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("idor compare failed: %v", err)
	}

	compFile := filepath.Join(runDir, workspace.IDORComparisonsFile)
	if _, err := os.Stat(compFile); os.IsNotExist(err) {
		t.Fatalf("idor_comparisons.json not created")
	}

	compData, _ := os.ReadFile(compFile)
	var comps []*idor.ComparisonResult
	if err := json.Unmarshal(compData, &comps); err != nil || len(comps) != 1 {
		t.Fatalf("expected 1 comparison, got %d", len(comps))
	}
	if comps[0].Status != idor.IDORStatusCrossTenant {
		t.Errorf("expected CrossTenant IDOR status, got %s", comps[0].Status)
	}

	// Verify finding was recorded in workspace
	rawFindings, err := ws.LoadRawFindings()
	if err != nil || len(rawFindings) != 1 {
		t.Fatalf("expected 1 finding recorded in raw_findings.json, got %d: %v", len(rawFindings), err)
	}

	// 5. Test `scoutr idor report --from <runDir>`
	reportOutFile := filepath.Join(runDir, "idor_report.md")
	RootCmd.SetArgs([]string{"idor", "report", "--from", runDir, "-o", reportOutFile})
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("idor report failed: %v", err)
	}

	repBytes, err := os.ReadFile(reportOutFile)
	if err != nil || !strings.Contains(string(repBytes), "Cross-Tenant Insecure Direct Object Reference") {
		t.Fatalf("report not generated properly: %s", string(repBytes))
	}
}
