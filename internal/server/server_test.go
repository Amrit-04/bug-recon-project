package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

func createTestWorkspaceWithArtifacts(t *testing.T, baseDir string) (*workspace.Workspace, string) {
	t.Helper()
	ws, err := workspace.NewRun(baseDir, "example.com")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	// 1. Inventory
	_ = ws.SaveInventory([]string{"api.example.com", "app.example.com"})

	// 2. Ports
	ports := []map[string]any{
		{"host": "api.example.com", "port": 443, "service": "https"},
	}
	_ = ws.SaveArtifact(workspace.PortsFile, ports)

	// 3. HTTPX
	httpx := []map[string]any{
		{"url": "https://api.example.com", "status_code": 200, "title": "API Gateway"},
	}
	_ = ws.SaveArtifact(workspace.HTTPXFile, httpx)

	// 4. Crawl
	crawl := []map[string]any{
		{"method": "GET", "endpoint": "https://api.example.com/v1/users"},
	}
	_ = ws.SaveArtifact(workspace.CrawlFile, crawl)

	// 5. Fuzz
	fuzz := []map[string]any{
		{"url": "https://api.example.com/admin", "status": 403, "length": 150},
	}
	_ = ws.SaveArtifact(workspace.FuzzFile, fuzz)

	// 6. Raw findings
	f := findings.NewFinding("TEST-1", "header-check", "https://api.example.com", "Missing HSTS", findings.SeverityHigh, findings.ConfidenceHigh)
	_ = ws.SaveRawFindings([]*findings.Finding{f})

	// 7. Validated findings
	vf := &validate.ValidatedFinding{
		Finding: f,
		Status:  validate.StatusVerified,
	}
	_ = ws.SaveValidatedFindings([]*validate.ValidatedFinding{vf})

	// 8. Triage
	tr := &triage.Report{
		Version:  triage.Version,
		Provider: "mock",
		Model:    "mock-model",
		Verdicts: []triage.Verdict{
			{FindingID: "TEST-1", Rank: 1, Classification: triage.LikelyTrue},
		},
	}
	_ = ws.SaveArtifact(workspace.TriageFile, tr)

	// 9. Drafts
	_, _ = ws.SaveDraft("TEST-1.md", "# Draft for TEST-1")

	// 10. Reports
	_ = ws.SaveReportMD("# Executive Report")
	_ = ws.SaveReportHTML("<html><body>Report</body></html>")

	runID := filepath.Base(ws.Dir)
	return ws, runID
}

func TestServerScopeAPI(t *testing.T) {
	tmpDir := t.TempDir()
	scopeFile := filepath.Join(tmpDir, "scope.yaml")
	_ = os.WriteFile(scopeFile, []byte("in_scope:\n  - \"example.com\"\nout_of_scope:\n  - \"admin.example.com\"\n"), 0644)

	s, err := New(Config{
		RunsDir:   filepath.Join(tmpDir, "runs"),
		ScopeFile: scopeFile,
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	handler := s.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/scope", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal scope: %v", err)
	}
	if inScope, ok := res["in_scope"].([]any); !ok || len(inScope) != 1 {
		t.Errorf("unexpected in_scope: %v", res["in_scope"])
	}
}

func TestServerRunsAndArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	runsDir := filepath.Join(tmpDir, "runs")
	_, runID := createTestWorkspaceWithArtifacts(t, runsDir)

	s, err := New(Config{
		RunsDir: runsDir,
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	handler := s.Routes()

	// 1. Test /api/runs
	req := httptest.NewRequest(http.MethodGet, "/api/runs", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/runs status = %d", rr.Code)
	}
	var runs []RunSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &runs); err != nil || len(runs) != 1 {
		t.Fatalf("unexpected runs: %v", runs)
	}
	if runs[0].ID != runID {
		t.Errorf("run ID = %q, want %q", runs[0].ID, runID)
	}

	// 2. Test Artifact Endpoints
	tests := []struct {
		url        string
		wantStatus int
		wantBody   string
	}{
		{"/api/runs/" + runID, http.StatusOK, "example.com"},
		{"/api/runs/" + runID + "/inventory", http.StatusOK, "api.example.com"},
		{"/api/runs/" + runID + "/ports", http.StatusOK, "443"},
		{"/api/runs/" + runID + "/httpx", http.StatusOK, "API Gateway"},
		{"/api/runs/" + runID + "/crawl", http.StatusOK, "users"},
		{"/api/runs/" + runID + "/fuzz", http.StatusOK, "admin"},
		{"/api/runs/" + runID + "/raw_findings", http.StatusOK, "TEST-1"},
		{"/api/runs/" + runID + "/findings", http.StatusOK, "Verified"},
		{"/api/runs/" + runID + "/triage", http.StatusOK, "likely_true"},
		{"/api/runs/" + runID + "/drafts", http.StatusOK, "TEST-1.md"},
		{"/api/runs/" + runID + "/drafts/TEST-1.md", http.StatusOK, "# Draft for TEST-1"},
		{"/api/runs/" + runID + "/report?format=md", http.StatusOK, "# Executive Report"},
		{"/api/runs/" + runID + "/report?format=html", http.StatusOK, "Report</body>"},
		// Invalid requests
		{"/api/runs/bad..id/inventory", http.StatusBadRequest, ""},
		{"/api/runs/nonexistent-run/inventory", http.StatusNotFound, ""},
		{"/api/runs/" + runID + "/unknown_artifact", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, tt.url, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if w.Code != tt.wantStatus {
			t.Errorf("GET %s status = %d, want %d", tt.url, w.Code, tt.wantStatus)
		}
		if tt.wantBody != "" && !strings.Contains(w.Body.String(), tt.wantBody) {
			t.Errorf("GET %s body does not contain %q. Got: %s", tt.url, tt.wantBody, w.Body.String())
		}
	}
}

func TestServerSPARouting(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	handler := s.Routes()

	// Root request should serve index.html
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET / status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "scoutr") {
		t.Errorf("index.html missing 'scoutr': %s", rr.Body.String())
	}

	// Unknown client route (e.g. /findings or /recon) should fallback to index.html (SPA)
	req = httptest.NewRequest(http.MethodGet, "/findings/view", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /findings/view status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "scoutr") {
		t.Errorf("SPA fallback failed for /findings/view: %s", rr.Body.String())
	}
}

func TestServerLifecycle(t *testing.T) {
	s, err := New(Config{
		Addr: "127.0.0.1:0", // random free port
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	if err := s.Start(); err != nil {
		t.Fatalf("Start server: %v", err)
	}
	defer s.Shutdown(context.Background())

	u := s.URL()
	if !strings.HasPrefix(u, "http://127.0.0.1:") {
		t.Errorf("unexpected URL: %s", u)
	}

	// Verify server responds
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(u + "/api/runs")
	if err != nil {
		t.Fatalf("GET server: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestServerLLMProviders(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	handler := s.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/llm/providers", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var providers []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &providers); err != nil {
		t.Fatalf("unmarshal providers: %v", err)
	}

	foundLMStudio := false
	foundLlamaCpp := false
	for _, p := range providers {
		if p["id"] == "lmstudio" {
			foundLMStudio = true
		}
		if p["id"] == "llamacpp" {
			foundLlamaCpp = true
		}
	}

	if !foundLMStudio {
		t.Error("expected lmstudio provider in response")
	}
	if !foundLlamaCpp {
		t.Error("expected llamacpp provider in response")
	}
}

func TestServerLLMTest(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/models") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "llama-3.2-3b-instruct"},
					{"id": "qwen2.5-coder-7b"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	s, err := New(Config{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	handler := s.Routes()

	// Test successful connectivity
	payload := `{"provider":"lmstudio","endpoint":"` + mockServer.URL + `/v1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(payload))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var res LLMTestResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal test response: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected ok=true, got false: %s", res.Error)
	}
	if len(res.Models) != 2 || res.Models[0] != "llama-3.2-3b-instruct" {
		t.Errorf("unexpected models: %v", res.Models)
	}

	// Test failed connectivity (unreachable port)
	badPayload := `{"provider":"lmstudio","endpoint":"http://127.0.0.1:59999/v1"}`
	badReq := httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(badPayload))
	badRR := httptest.NewRecorder()
	handler.ServeHTTP(badRR, badReq)

	var badRes LLMTestResponse
	_ = json.Unmarshal(badRR.Body.Bytes(), &badRes)
	if badRes.OK {
		t.Error("expected ok=false for unreachable endpoint")
	}
}

func TestServerRunTriage(t *testing.T) {
	tmpDir := t.TempDir()
	runsDir := filepath.Join(tmpDir, "runs")
	_, runID := createTestWorkspaceWithArtifacts(t, runsDir)

	mockRunnerCalled := false
	s, err := New(Config{
		RunsDir: runsDir,
		TriageRunner: func(ctx context.Context, list []*validate.ValidatedFinding, techByHost map[string][]string, opts triage.Options) (*triage.Report, error) {
			mockRunnerCalled = true
			return &triage.Report{
				Version:  triage.Version,
				Provider: opts.Client.Name(),
				Model:    opts.Model,
				Batches:  1,
				Counts:   map[string]int{"likely_true": 1},
				Verdicts: []triage.Verdict{
					{
						FindingID:      "TEST-1",
						Classification: triage.LikelyTrue,
						Rationale:      "verified by LM Studio test runner",
						Confidence:     95,
						Rank:           1,
					},
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	handler := s.Routes()

	// 1. Valid triage request with LM Studio
	body := `{"provider":"lmstudio","endpoint":"http://127.0.0.1:1234/v1","model":"llama-3.2-3b-instruct"}`
	req := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/triage", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. Body: %s", rr.Code, rr.Body.String())
	}
	if !mockRunnerCalled {
		t.Error("expected custom TriageRunner to be invoked")
	}

	var rep triage.Report
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal triage report: %v", err)
	}
	if rep.Provider != "lmstudio" || rep.Model != "llama-3.2-3b-instruct" {
		t.Errorf("unexpected report meta: provider=%s, model=%s", rep.Provider, rep.Model)
	}
	if len(rep.Verdicts) != 1 || rep.Verdicts[0].Classification != triage.LikelyTrue {
		t.Errorf("unexpected verdicts: %+v", rep.Verdicts)
	}

	// 2. Empty model should return 400
	badBody := `{"provider":"lmstudio","endpoint":"http://127.0.0.1:1234/v1","model":""}`
	badReq := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/triage", strings.NewReader(badBody))
	badRR := httptest.NewRecorder()
	handler.ServeHTTP(badRR, badReq)

	if badRR.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty model", badRR.Code)
	}
}
