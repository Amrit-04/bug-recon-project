package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/idor"
	"github.com/scoutr/scoutr/internal/rce"
	"github.com/scoutr/scoutr/internal/tools"
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

func TestServerToolsAPI(t *testing.T) {
	runner := tools.NewMockRunner()
	runner.RegisterTool("naabu", "/usr/bin/naabu", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte("naabu v2.3.1"), nil, nil
	})

	s, err := New(Config{
		RunsDir: t.TempDir(),
		Runner:  runner,
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/tools", nil)
	rr := httptest.NewRecorder()
	s.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var statuses []tools.ToolStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &statuses); err != nil {
		t.Fatalf("unmarshal tools: %v", err)
	}

	if len(statuses) == 0 {
		t.Fatal("expected non-empty tools list")
	}

	var foundNaabu bool
	for _, st := range statuses {
		if st.Binary == "naabu" {
			foundNaabu = true
			if !st.Installed {
				t.Error("expected naabu to be installed via mock runner")
			}
			if st.Version != "2.3.1" {
				t.Errorf("expected version 2.3.1, got %s", st.Version)
			}
		}
	}
	if !foundNaabu {
		t.Error("naabu not found in tools list")
	}
}

func TestServerScanLifecycle(t *testing.T) {
	runner := tools.NewMockRunner()

	s, err := New(Config{
		RunsDir: t.TempDir(),
		Runner:  runner,
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	handler := s.Routes()

	// 1. Initial status should be not running
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/scan/status", nil)
	rrStatus := httptest.NewRecorder()
	handler.ServeHTTP(rrStatus, reqStatus)
	if rrStatus.Code != http.StatusOK {
		t.Fatalf("get status code = %d, want 200", rrStatus.Code)
	}
	var initStatus ScanStatus
	_ = json.Unmarshal(rrStatus.Body.Bytes(), &initStatus)
	if initStatus.Running {
		t.Error("expected initial scan status to be not running")
	}

	// 2. Start a scan (DryRun = true)
	payload := `{"target":"api.example.com","in_scope":["api.example.com"],"dry_run":true}`
	reqStart := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(payload))
	rrStart := httptest.NewRecorder()
	handler.ServeHTTP(rrStart, reqStart)

	if rrStart.Code != http.StatusOK {
		t.Fatalf("start scan code = %d, want 200: %s", rrStart.Code, rrStart.Body.String())
	}

	// Wait briefly for dry-run to complete in background
	time.Sleep(100 * time.Millisecond)

	// 3. Status should have recorded logs
	reqStatus2 := httptest.NewRequest(http.MethodGet, "/api/scan/status", nil)
	rrStatus2 := httptest.NewRecorder()
	handler.ServeHTTP(rrStatus2, reqStatus2)
	var postStatus ScanStatus
	_ = json.Unmarshal(rrStatus2.Body.Bytes(), &postStatus)
	if len(postStatus.Logs) == 0 {
		t.Error("expected logs in scan status after dry-run")
	}

	// 4. Cancel when not running returns not_running
	reqCancel := httptest.NewRequest(http.MethodPost, "/api/scan/cancel", nil)
	rrCancel := httptest.NewRecorder()
	handler.ServeHTTP(rrCancel, reqCancel)
	if rrCancel.Code != http.StatusOK {
		t.Fatalf("cancel code = %d, want 200", rrCancel.Code)
	}
	if !strings.Contains(rrCancel.Body.String(), "not_running") {
		t.Errorf("expected not_running response, got %s", rrCancel.Body.String())
	}
}

func TestServerModularToolExecution(t *testing.T) {
	baseDir := t.TempDir()
	ws, runID := createTestWorkspaceWithArtifacts(t, baseDir)

	runner := tools.NewMockRunner()
	runner.RegisterTool("naabu", "/usr/bin/naabu", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte("api.example.com:443\n"), nil, nil
	})
	runner.RegisterTool("httpx", "/usr/bin/httpx", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte(`{"url":"https://api.example.com","status_code":200,"title":"API"}` + "\n"), nil, nil
	})

	s, err := New(Config{
		RunsDir: baseDir,
		Runner:  runner,
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	handler := s.Routes()

	// 1. Run subdomains
	reqSub := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/tools/subdomains", strings.NewReader(`{"in_scope":["api.example.com"]}`))
	rrSub := httptest.NewRecorder()
	handler.ServeHTTP(rrSub, reqSub)
	if rrSub.Code != http.StatusOK {
		t.Fatalf("subdomains tool code = %d, want 200: %s", rrSub.Code, rrSub.Body.String())
	}

	// 2. Run ports
	reqPorts := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/tools/ports", strings.NewReader(`{}`))
	rrPorts := httptest.NewRecorder()
	handler.ServeHTTP(rrPorts, reqPorts)
	if rrPorts.Code != http.StatusOK {
		t.Fatalf("ports tool code = %d, want 200: %s", rrPorts.Code, rrPorts.Body.String())
	}

	// 3. Run probe
	reqProbe := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/tools/probe", strings.NewReader(`{}`))
	rrProbe := httptest.NewRecorder()
	handler.ServeHTTP(rrProbe, reqProbe)
	if rrProbe.Code != http.StatusOK {
		t.Fatalf("probe tool code = %d, want 200: %s", rrProbe.Code, rrProbe.Body.String())
	}

	// 4. Run validate (7-Check Gate)
	reqVal := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/tools/validate", strings.NewReader(`{}`))
	rrVal := httptest.NewRecorder()
	handler.ServeHTTP(rrVal, reqVal)
	if rrVal.Code != http.StatusOK {
		t.Fatalf("validate tool code = %d, want 200: %s", rrVal.Code, rrVal.Body.String())
	}

	// 5. Run unknown tool
	reqBad := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/tools/unknown-tool", strings.NewReader(`{}`))
	rrBad := httptest.NewRecorder()
	handler.ServeHTTP(rrBad, reqBad)
	if rrBad.Code != http.StatusBadRequest {
		t.Errorf("unknown tool code = %d, want 400", rrBad.Code)
	}

	// Ensure workspace still valid
	if _, err := ws.LoadInventory(); err != nil {
		t.Errorf("load inventory after runs: %v", err)
	}
}

func TestStatusAndScopeAPIs(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := New(Config{
		RunsDir: filepath.Join(tmpDir, "runs"),
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	handler := s.Routes()

	// 1. Status API
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rrStatus := httptest.NewRecorder()
	handler.ServeHTTP(rrStatus, reqStatus)
	if rrStatus.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rrStatus.Code)
	}

	var statusMap map[string]any
	_ = json.Unmarshal(rrStatus.Body.Bytes(), &statusMap)
	if statusMap["status"] != "online" {
		t.Errorf("status = %v, want online", statusMap["status"])
	}

	// 2. Scope POST validate
	reqScope := httptest.NewRequest(http.MethodPost, "/api/scope", strings.NewReader(`{
		"in_scope": ["example.com", "*.example.com"],
		"out_of_scope": ["admin.example.com"],
		"test_target": "https://api.example.com/test"
	}`))
	rrScope := httptest.NewRecorder()
	handler.ServeHTTP(rrScope, reqScope)
	if rrScope.Code != http.StatusOK {
		t.Fatalf("scope post code = %d, want 200", rrScope.Code)
	}

	var scopeResp map[string]any
	_ = json.Unmarshal(rrScope.Body.Bytes(), &scopeResp)
	if scopeResp["in_scope"] != true {
		t.Errorf("expected test_target in_scope = true, got %v", scopeResp["in_scope"])
	}
}

func TestWorkspacesAPI(t *testing.T) {
	tmpDir := t.TempDir()
	s, err := New(Config{
		RunsDir: filepath.Join(tmpDir, "runs"),
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	handler := s.Routes()

	// Create workspace
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/workspaces", strings.NewReader(`{"target":"acme.org"}`))
	rrCreate := httptest.NewRecorder()
	handler.ServeHTTP(rrCreate, reqCreate)
	if rrCreate.Code != http.StatusCreated {
		t.Fatalf("create workspace code = %d, want 201: %s", rrCreate.Code, rrCreate.Body.String())
	}

	var wsResp map[string]any
	_ = json.Unmarshal(rrCreate.Body.Bytes(), &wsResp)
	runID, _ := wsResp["id"].(string)
	if runID == "" {
		t.Fatal("expected non-empty workspace id")
	}

	// List workspaces
	reqList := httptest.NewRequest(http.MethodGet, "/api/workspaces", nil)
	rrList := httptest.NewRecorder()
	handler.ServeHTTP(rrList, reqList)
	if rrList.Code != http.StatusOK {
		t.Fatalf("list workspaces code = %d, want 200", rrList.Code)
	}
	var runs []RunSummary
	_ = json.Unmarshal(rrList.Body.Bytes(), &runs)
	if len(runs) != 1 || runs[0].ID != runID {
		t.Errorf("expected run %s in list, got %+v", runID, runs)
	}
}

func TestJobManagerAndSSEEvents(t *testing.T) {
	tmpDir := t.TempDir()
	broker := NewEventBroker(100)
	storagePath := filepath.Join(tmpDir, "jobs.json")

	jm, err := NewJobManager(storagePath, 2, broker)
	if err != nil {
		t.Fatalf("NewJobManager: %v", err)
	}
	defer jm.Close()

	// Subscribe to broker
	eventsCh, unsub := broker.Subscribe("")
	defer unsub()

	// Submit a fast background job
	doneCh := make(chan struct{})
	job, err := jm.Submit("test_job", "ws-1", "example.com", nil, func(ctx context.Context, j *Job, update func(int, string, string, int), emitLog func(string)) error {
		update(1, "processing", "Doing work", 50)
		emitLog("Job progress step")
		close(doneCh)
		return nil
	})
	if err != nil {
		t.Fatalf("Submit job: %v", err)
	}

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("job timed out")
	}

	// Wait briefly for completion
	time.Sleep(100 * time.Millisecond)

	j, err := jm.GetJob(job.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if j.Status != JobStatusCompleted {
		t.Errorf("job status = %s, want Completed", j.Status)
	}

	// Check that broker received events
	receivedProgress := false
	receivedLog := false
	for len(eventsCh) > 0 {
		ev := <-eventsCh
		if ev.Type == EventProgress {
			receivedProgress = true
		}
		if ev.Type == EventLog {
			receivedLog = true
		}
	}
	if !receivedProgress {
		t.Error("expected EventProgress in SSE broker")
	}
	if !receivedLog {
		t.Error("expected EventLog in SSE broker")
	}

	// Test cancellation
	cancelDone := make(chan struct{})
	jobCancel, err := jm.Submit("cancel_job", "ws-1", "example.com", nil, func(ctx context.Context, j *Job, update func(int, string, string, int), emitLog func(string)) error {
		<-ctx.Done()
		close(cancelDone)
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("Submit cancel job: %v", err)
	}

	// Wait for job to start running
	time.Sleep(50 * time.Millisecond)

	err = jm.CancelJob(jobCancel.ID)
	if err != nil {
		t.Fatalf("CancelJob: %v", err)
	}

	select {
	case <-cancelDone:
	case <-time.After(2 * time.Second):
		t.Fatal("context cancellation did not propagate")
	}

	time.Sleep(50 * time.Millisecond)
	jc, _ := jm.GetJob(jobCancel.ID)
	if jc.Status != JobStatusCancelled {
		t.Errorf("expected JobStatusCancelled, got %s", jc.Status)
	}
}

func TestEndpointsExplorerAPI(t *testing.T) {
	baseDir := t.TempDir()
	ws, runID := createTestWorkspaceWithArtifacts(t, baseDir)

	// Save endpoints artifact
	endpointsList := []*endpoints.Endpoint{
		{
			Origin:           "https://api.example.com",
			URL:              "https://api.example.com/api/v1/users/{id}",
			NormalizedRoute:  "/api/v1/users/{id}",
			Methods:          []string{"GET", "POST"},
			QueryParams:      []string{"filter", "limit"},
			BodyFields:       []string{"role"},
			TechFingerprints: []string{"nginx", "django"},
			Classifications: []endpoints.ClassificationResult{
				{Category: endpoints.ClassUserData, Priority: 8},
			},
			AuthObservations: []endpoints.AuthObservation{
				{Status: endpoints.AuthStatusAuthenticated, PrincipalLabel: "user_a"},
			},
		},
		{
			Origin:           "https://admin.example.com",
			URL:              "https://admin.example.com/upload",
			NormalizedRoute:  "/upload",
			Methods:          []string{"POST"},
			TechFingerprints: []string{"express"},
			Classifications: []endpoints.ClassificationResult{
				{Category: endpoints.ClassFileProcess, Priority: 9},
			},
			AuthObservations: []endpoints.AuthObservation{
				{Status: endpoints.AuthStatusAnonymous},
			},
		},
	}
	_ = ws.SaveArtifact(workspace.EndpointsFile, endpointsList)

	s, err := New(Config{RunsDir: baseDir})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	defer s.jobs.Close()
	handler := s.Routes()

	// 1. Get all endpoints
	reqAll := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/endpoints", nil)
	rrAll := httptest.NewRecorder()
	handler.ServeHTTP(rrAll, reqAll)
	if rrAll.Code != http.StatusOK {
		t.Fatalf("endpoints code = %d, want 200", rrAll.Code)
	}

	var respAll struct {
		Total     int                   `json:"total"`
		Endpoints []*endpoints.Endpoint `json:"endpoints"`
	}
	_ = json.Unmarshal(rrAll.Body.Bytes(), &respAll)
	if respAll.Total != 2 {
		t.Errorf("total endpoints = %d, want 2", respAll.Total)
	}

	// 2. Filter by host
	reqHost := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/endpoints?host=admin.example.com", nil)
	rrHost := httptest.NewRecorder()
	handler.ServeHTTP(rrHost, reqHost)
	var respHost struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rrHost.Body.Bytes(), &respHost)
	if respHost.Total != 1 {
		t.Errorf("filtered by host = %d, want 1", respHost.Total)
	}

	// 3. Filter by method
	reqMethod := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/endpoints?method=GET", nil)
	rrMethod := httptest.NewRecorder()
	handler.ServeHTTP(rrMethod, reqMethod)
	var respMethod struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rrMethod.Body.Bytes(), &respMethod)
	if respMethod.Total != 1 {
		t.Errorf("filtered by method = %d, want 1", respMethod.Total)
	}
}

func TestAuthProfilesAndIDORAPIs(t *testing.T) {
	baseDir := t.TempDir()
	ws, runID := createTestWorkspaceWithArtifacts(t, baseDir)

	s, err := New(Config{RunsDir: baseDir})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	defer s.jobs.Close()
	handler := s.Routes()

	// 1. Save Profile A (User A)
	reqProfA := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/auth/profiles", strings.NewReader(`{
		"principal_label": "user_a",
		"tenant_label": "tenant_1",
		"instance_label": "default",
		"role_label": "admin",
		"auth_type": "bearer",
		"token": "secret_token_12345"
	}`))
	rrProfA := httptest.NewRecorder()
	handler.ServeHTTP(rrProfA, reqProfA)
	if rrProfA.Code != http.StatusOK {
		t.Fatalf("save profile A code = %d, want 200: %s", rrProfA.Code, rrProfA.Body.String())
	}

	// 2. Save Profile B (User B)
	reqProfB := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/auth/profiles", strings.NewReader(`{
		"principal_label": "user_b",
		"tenant_label": "tenant_2",
		"instance_label": "default",
		"role_label": "member",
		"auth_type": "bearer",
		"token": "different_secret_67890"
	}`))
	rrProfB := httptest.NewRecorder()
	handler.ServeHTTP(rrProfB, reqProfB)
	if rrProfB.Code != http.StatusOK {
		t.Fatalf("save profile B code = %d, want 200", rrProfB.Code)
	}

	// 3. List profiles - credentials MUST be redacted!
	reqListProf := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/auth/profiles", nil)
	rrListProf := httptest.NewRecorder()
	handler.ServeHTTP(rrListProf, reqListProf)
	if rrListProf.Code != http.StatusOK {
		t.Fatalf("list profiles code = %d, want 200", rrListProf.Code)
	}

	var summaries []auth.ProfileSummary
	_ = json.Unmarshal(rrListProf.Body.Bytes(), &summaries)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(summaries))
	}
	// Check secret redaction
	bodyStr := rrListProf.Body.String()
	if strings.Contains(bodyStr, "secret_token_12345") || strings.Contains(bodyStr, "different_secret_67890") {
		t.Fatalf("RAW CREDENTIALS LEAKED IN PROFILES API RESPONSE! Body: %s", bodyStr)
	}

	// 4. Save candidates artifact to test IDOR endpoints
	objInv := idor.NewObjectInventory()
	objInv.Add(idor.ObjectReference{
		ID:             "cand-1",
		ObjectID:       "1001",
		Location:       idor.LocationPath,
		ParamName:      "id",
		RouteTemplate:  "/api/docs/{id}",
		TargetURL:      "https://example.com/api/docs/1001",
		Method:         "GET",
		OwnerPrincipal: "user_a",
		OwnerTenant:    "tenant_1",
		AccessPolicy:   idor.AccessPolicyPrivate,
	})
	_ = objInv.SaveJSON(filepath.Join(ws.Dir, workspace.IDORCandidatesFile))

	// 5. List candidates
	reqCand := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/idor/candidates", nil)
	rrCand := httptest.NewRecorder()
	handler.ServeHTTP(rrCand, reqCand)
	if rrCand.Code != http.StatusOK {
		t.Fatalf("list candidates code = %d, want 200", rrCand.Code)
	}
	var candResp struct {
		Total      int                    `json:"total"`
		Candidates []idor.ObjectReference `json:"candidates"`
	}
	_ = json.Unmarshal(rrCand.Body.Bytes(), &candResp)
	if candResp.Total != 1 || candResp.Candidates[0].ObjectID != "1001" {
		t.Errorf("expected 1 candidate with id 1001, got %+v", candResp)
	}

	// 6. Update candidate policy
	reqPolicy := httptest.NewRequest(http.MethodPut, "/api/runs/"+runID+"/idor/candidates/cand-1/policy", strings.NewReader(`{
		"access_policy": "explicitly_shared",
		"allowed_roles": ["admin"]
	}`))
	rrPolicy := httptest.NewRecorder()
	handler.ServeHTTP(rrPolicy, reqPolicy)
	if rrPolicy.Code != http.StatusOK {
		t.Fatalf("update policy code = %d, want 200: %s", rrPolicy.Code, rrPolicy.Body.String())
	}
	var updatedCand idor.ObjectReference
	_ = json.Unmarshal(rrPolicy.Body.Bytes(), &updatedCand)
	if updatedCand.AccessPolicy != "explicitly_shared" {
		t.Errorf("access policy = %s, want explicitly_shared", updatedCand.AccessPolicy)
	}
}

func TestServerHostHeaderValidation(t *testing.T) {
	s, err := New(Config{
		RunsDir: t.TempDir(),
		Addr:    "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start server: %v", err)
	}
	defer s.Shutdown(context.Background())

	baseURL := s.URL()
	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Valid Host header (127.0.0.1:port)
	req1, _ := http.NewRequest(http.MethodGet, baseURL+"/api/status", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("GET /api/status: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for valid host, got %d", resp1.StatusCode)
	}

	// 2. Invalid Host header (evil.com) -> DNS rebinding attempt
	req2, _ := http.NewRequest(http.MethodGet, baseURL+"/api/status", nil)
	req2.Host = "evil.com"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("GET /api/status with evil.com: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for evil.com Host header, got %d", resp2.StatusCode)
	}

	// 3. Valid Host header with localhost
	req3, _ := http.NewRequest(http.MethodGet, baseURL+"/api/status", nil)
	req3.Host = "localhost"
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatalf("GET /api/status with localhost: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for localhost Host header, got %d", resp3.StatusCode)
	}
}

func TestServerAntiCSRFAndToken(t *testing.T) {
	s, err := New(Config{
		RunsDir: t.TempDir(),
		Addr:    "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start server: %v", err)
	}
	defer s.Shutdown(context.Background())

	baseURL := s.URL()
	client := &http.Client{Timeout: 3 * time.Second}

	// 1. Retrieve API token
	respToken, err := client.Get(baseURL + "/api/auth/token")
	if err != nil {
		t.Fatalf("GET /api/auth/token: %v", err)
	}
	defer respToken.Body.Close()
	if respToken.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/auth/token status = %d", respToken.StatusCode)
	}
	var tokenData struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(respToken.Body).Decode(&tokenData)
	if tokenData.Token == "" || len(tokenData.Token) != 64 {
		t.Errorf("expected 64-char hex token, got %q", tokenData.Token)
	}

	// 2. Unauthenticated POST over TCP without headers -> 403 Forbidden
	reqNoAuth, _ := http.NewRequest(http.MethodPost, baseURL+"/api/workspaces", strings.NewReader(`{"target":"csrf-test.com"}`))
	respNoAuth, err := client.Do(reqNoAuth)
	if err != nil {
		t.Fatalf("POST /api/workspaces without auth: %v", err)
	}
	respNoAuth.Body.Close()
	if respNoAuth.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for state change without token/headers, got %d", respNoAuth.StatusCode)
	}

	// 3. POST with X-Requested-With: Scoutr -> 201 Created
	reqReqWith, _ := http.NewRequest(http.MethodPost, baseURL+"/api/workspaces", strings.NewReader(`{"target":"reqwith-test.com"}`))
	reqReqWith.Header.Set("X-Requested-With", "Scoutr")
	respReqWith, err := client.Do(reqReqWith)
	if err != nil {
		t.Fatalf("POST /api/workspaces with X-Requested-With: %v", err)
	}
	respReqWith.Body.Close()
	if respReqWith.StatusCode != http.StatusCreated {
		t.Errorf("expected 201 Created with X-Requested-With: Scoutr, got %d", respReqWith.StatusCode)
	}

	// 4. POST with X-Scoutr-Token -> 201 Created
	reqTokenAuth, _ := http.NewRequest(http.MethodPost, baseURL+"/api/workspaces", strings.NewReader(`{"target":"token-test.com"}`))
	reqTokenAuth.Header.Set("X-Scoutr-Token", tokenData.Token)
	respTokenAuth, err := client.Do(reqTokenAuth)
	if err != nil {
		t.Fatalf("POST /api/workspaces with X-Scoutr-Token: %v", err)
	}
	respTokenAuth.Body.Close()
	if respTokenAuth.StatusCode != http.StatusCreated {
		t.Errorf("expected 201 Created with X-Scoutr-Token, got %d", respTokenAuth.StatusCode)
	}

	// 5. POST with X-Requested-With but cross-origin attacker Origin -> 403 Forbidden
	reqCross, _ := http.NewRequest(http.MethodPost, baseURL+"/api/workspaces", strings.NewReader(`{"target":"cross-test.com"}`))
	reqCross.Header.Set("X-Requested-With", "Scoutr")
	reqCross.Header.Set("Origin", "https://attacker.evil.com")
	respCross, err := client.Do(reqCross)
	if err != nil {
		t.Fatalf("POST /api/workspaces with attacker Origin: %v", err)
	}
	respCross.Body.Close()
	if respCross.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for cross-origin state change, got %d", respCross.StatusCode)
	}
}

func TestServerPathTraversalHardening(t *testing.T) {
	tmpDir := t.TempDir()
	runsDir := filepath.Join(tmpDir, "runs")
	s, err := New(Config{RunsDir: runsDir})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	handler := s.Routes()

	// 1. Invalid run ID with ..
	req1 := httptest.NewRequest(http.MethodGet, "/api/runs/..%2F..%2Fetc/inventory", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for traversal run ID, got %d", rr1.Code)
	}

	// 2. Invalid workspace creation target with path traversal
	req2 := httptest.NewRequest(http.MethodPost, "/api/workspaces", strings.NewReader(`{"target":"../../escaped"}`))
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for traversal workspace target, got %d", rr2.Code)
	}

	// 3. Invalid job ID with path traversal
	req3 := httptest.NewRequest(http.MethodGet, "/api/jobs/..%2Fbadjob", nil)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for traversal job ID, got %d", rr3.Code)
	}
}

func TestSSERingBufferChronologicalAndOverrun(t *testing.T) {
	broker := NewEventBroker(5)

	// Broadcast 10 events (IDs 1 through 10)
	for i := 1; i <= 10; i++ {
		broker.Broadcast("job-1", EventProgress, map[string]int{"step": i})
	}

	// Ring buffer has capacity 5, so IDs 1..5 were overwritten. Buffer contains IDs 6..10.
	// Client asks for events since ID 2: this is a buffer overrun (missed 3, 4, 5).
	events := broker.EventsSince(2, "job-1")
	if len(events) == 0 {
		t.Fatalf("expected replayed events, got 0")
	}

	// First event should be EventSyncRequired
	if events[0].Type != EventSyncRequired {
		t.Errorf("expected first event to be %s, got %s", EventSyncRequired, events[0].Type)
	}

	// Remaining events must be strictly ascending by ID
	for i := 2; i < len(events); i++ {
		if events[i].ID <= events[i-1].ID {
			t.Errorf("events out of order: events[%d].ID=%d <= events[%d].ID=%d",
				i, events[i].ID, i-1, events[i-1].ID)
		}
	}
}

func TestJobManagerAtomicSaveAndQueueSaturation(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "jobs.json")
	broker := NewEventBroker(100)

	// Test with 0 workers initially to fill queue
	jm, err := NewJobManager(storagePath, 1, broker)
	if err != nil {
		t.Fatalf("NewJobManager: %v", err)
	}
	defer jm.Close()

	// Fill queue to capacity (100)
	var lastErr error
	for i := 0; i < 110; i++ {
		_, err := jm.Submit("tool_run", "ws-1", "target.com", nil, func(ctx context.Context, job *Job, update func(int, string, string, int), emitLog func(string)) error {
			time.Sleep(50 * time.Millisecond)
			return nil
		})
		if err != nil {
			lastErr = err
			break
		}
	}

	// Should handle queue saturation cleanly
	if lastErr == nil {
		t.Log("Note: queue handled submissions within worker throughput")
	} else if !strings.Contains(lastErr.Error(), "queue is full") {
		t.Errorf("unexpected submission error: %v", lastErr)
	}

	// Verify storage file exists and contains valid JSON
	data, err := os.ReadFile(storagePath)
	if err != nil {
		t.Fatalf("read jobs.json: %v", err)
	}
	var loaded []*Job
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("jobs.json unmarshal: %v", err)
	}
	if len(loaded) == 0 {
		t.Error("expected stored jobs in jobs.json")
	}
}

func TestRCERESTAPI(t *testing.T) {
	baseDir := t.TempDir()
	ws, runID := createTestWorkspaceWithArtifacts(t, baseDir)

	// 1. Write mock endpoints.json
	eps := []*endpoints.Endpoint{
		{
			Origin:           "https://example.com",
			URL:              "https://example.com/api/v1/diag/ping",
			NormalizedRoute:  "/api/v1/diag/ping",
			Methods:          []string{"POST"},
			QueryParams:      []string{"target"},
			BodyFields:       []string{"host", "args"},
			TechFingerprints: []string{"Linux", "Spring Framework 5.3.17"},
		},
		{
			Origin:           "https://example.com",
			URL:              "https://example.com/render/template",
			NormalizedRoute:  "/render/template",
			Methods:          []string{"GET"},
			QueryParams:      []string{"template"},
			TechFingerprints: []string{"Jinja2"},
		},
	}
	_ = ws.SaveArtifact(workspace.EndpointsFile, eps)

	s, err := New(Config{RunsDir: baseDir})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	defer s.jobs.Close()
	handler := s.Routes()

	// Test 1: Discover RCE attack surfaces
	reqDisc := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/rce/discover", nil)
	reqDisc.Header.Set("X-Requested-With", "Scoutr")
	reqDisc.Header.Set("X-Scoutr-Token", s.apiToken)
	rrDisc := httptest.NewRecorder()
	handler.ServeHTTP(rrDisc, reqDisc)

	if rrDisc.Code != http.StatusAccepted {
		t.Fatalf("POST rce/discover status = %d, want 202 (body: %s)", rrDisc.Code, rrDisc.Body.String())
	}

	// Wait briefly for background discover job to complete
	time.Sleep(300 * time.Millisecond)

	// Test 2: List candidates
	reqList := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/rce/candidates", nil)
	rrList := httptest.NewRecorder()
	handler.ServeHTTP(rrList, reqList)

	if rrList.Code != http.StatusOK {
		t.Fatalf("GET rce/candidates status = %d, want 200", rrList.Code)
	}

	var candsResp struct {
		Total      int                 `json:"total"`
		Candidates []*rce.RCECandidate `json:"candidates"`
	}
	if err := json.Unmarshal(rrList.Body.Bytes(), &candsResp); err != nil {
		t.Fatalf("decode candidates response: %v", err)
	}

	if candsResp.Total == 0 || len(candsResp.Candidates) == 0 {
		t.Fatalf("expected discovered candidates, got %d", candsResp.Total)
	}
	cid := candsResp.Candidates[0].ID

	// Test 3: Get single candidate
	reqGet := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/rce/candidates/"+cid, nil)
	rrGet := httptest.NewRecorder()
	handler.ServeHTTP(rrGet, reqGet)

	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET rce/candidates/{cid} status = %d, want 200", rrGet.Code)
	}
	var singleCand rce.RCECandidate
	_ = json.Unmarshal(rrGet.Body.Bytes(), &singleCand)
	if singleCand.ID != cid {
		t.Errorf("candidate ID mismatch: got %s, want %s", singleCand.ID, cid)
	}

	// Test 4: Update candidate status and notes
	updateBody := `{"status": "needs_manual_review", "notes": "Requires authorized security review"}`
	reqUp := httptest.NewRequest(http.MethodPut, "/api/runs/"+runID+"/rce/candidates/"+cid, strings.NewReader(updateBody))
	reqUp.Header.Set("X-Requested-With", "Scoutr")
	reqUp.Header.Set("X-Scoutr-Token", s.apiToken)
	rrUp := httptest.NewRecorder()
	handler.ServeHTTP(rrUp, reqUp)

	if rrUp.Code != http.StatusOK {
		t.Fatalf("PUT rce/candidates/{cid} status = %d, want 200", rrUp.Code)
	}

	// Test 5: Get Overview
	reqOver := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/rce/overview", nil)
	rrOver := httptest.NewRecorder()
	handler.ServeHTTP(rrOver, reqOver)

	if rrOver.Code != http.StatusOK {
		t.Fatalf("GET rce/overview status = %d, want 200", rrOver.Code)
	}
	var overview rce.RCEOverview
	_ = json.Unmarshal(rrOver.Body.Bytes(), &overview)
	if overview.TotalCandidates == 0 {
		t.Errorf("expected overview.TotalCandidates > 0, got 0")
	}

	// Test 6: Get Advisories
	reqAdv := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/rce/advisories", nil)
	rrAdv := httptest.NewRecorder()
	handler.ServeHTTP(rrAdv, reqAdv)

	if rrAdv.Code != http.StatusOK {
		t.Fatalf("GET rce/advisories status = %d, want 200", rrAdv.Code)
	}

	// Test 7: Validate Candidate (passive profile)
	valPayload := fmt.Sprintf(`{"candidate_id": "%s", "profile": "passive"}`, cid)
	reqVal := httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/rce/validate", strings.NewReader(valPayload))
	reqVal.Header.Set("X-Requested-With", "Scoutr")
	reqVal.Header.Set("X-Scoutr-Token", s.apiToken)
	rrVal := httptest.NewRecorder()
	handler.ServeHTTP(rrVal, reqVal)

	if rrVal.Code != http.StatusAccepted {
		t.Fatalf("POST rce/validate status = %d, want 202", rrVal.Code)
	}

	// Test 8: Get Report
	reqRep := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/rce/report", nil)
	rrRep := httptest.NewRecorder()
	handler.ServeHTTP(rrRep, reqRep)

	if rrRep.Code != http.StatusOK {
		t.Fatalf("GET rce/report status = %d, want 200", rrRep.Code)
	}
	var reportResp struct {
		Markdown string `json:"markdown"`
	}
	_ = json.Unmarshal(rrRep.Body.Bytes(), &reportResp)
	if !strings.Contains(reportResp.Markdown, "Scoutr RCE Research and Attack Surface Report") {
		t.Errorf("expected report title in report response markdown")
	}
	time.Sleep(150 * time.Millisecond)
}
