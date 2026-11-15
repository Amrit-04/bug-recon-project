package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/pipeline"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/triage"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
	"github.com/scoutr/scoutr/web"
)

// TriageRunnerFunc executes triage for a workspace run.
type TriageRunnerFunc func(ctx context.Context, list []*validate.ValidatedFinding, techByHost map[string][]string, opts triage.Options) (*triage.Report, error)

// Config options for the local API and UI server.
type Config struct {
	RunsDir      string
	ScopeFile    string
	Addr         string
	TriageRunner TriageRunnerFunc
	Runner       tools.CommandRunner
}

// Server provides the local HTTP API and serves the embedded SPA dashboard.
type Server struct {
	cfg          Config
	listener     net.Listener
	httpServer   *http.Server
	distFS       fs.FS
	triageRunner TriageRunnerFunc
	runner       tools.CommandRunner

	scanMu     sync.RWMutex
	scanStatus ScanStatus
	scanCancel context.CancelFunc
}

// ScanStatus tracks real-time progress, stages, and logs of an active or recent scan.
type ScanStatus struct {
	Running     bool     `json:"running"`
	RunID       string   `json:"run_id,omitempty"`
	Target      string   `json:"target,omitempty"`
	StageIndex  int      `json:"stage_index"`
	TotalStages int      `json:"total_stages"`
	StageName   string   `json:"stage_name,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	Error       string   `json:"error,omitempty"`
	Logs        []string `json:"logs"`
	StartTime   string   `json:"start_time,omitempty"`
	EndTime     string   `json:"end_time,omitempty"`
}

// StartScanRequest defines payload for initiating an automated security scan.
type StartScanRequest struct {
	Target     string   `json:"target"`
	InScope    []string `json:"in_scope,omitempty"`
	OutOfScope []string `json:"out_of_scope,omitempty"`
	ScanMode   string   `json:"scan_mode,omitempty"` // "standard", "passive", "custom"
	SkipPorts  bool     `json:"skip_ports,omitempty"`
	SkipCrawl  bool     `json:"skip_crawl,omitempty"`
	SkipFuzz   bool     `json:"skip_fuzz,omitempty"`
	SkipXSS    bool     `json:"skip_xss,omitempty"`
	SkipNuclei bool     `json:"skip_nuclei,omitempty"`
	NucleiTags []string `json:"nuclei_tags,omitempty"`
	RateLimit  int      `json:"rate_limit,omitempty"`
	DryRun     bool     `json:"dry_run,omitempty"`
}

// ToolRunRequest defines optional overrides when triggering a specific tool on demand.
type ToolRunRequest struct {
	InScope    []string `json:"in_scope,omitempty"`
	OutOfScope []string `json:"out_of_scope,omitempty"`
	RateLimit  int      `json:"rate_limit,omitempty"`
	TopPorts   int      `json:"top_ports,omitempty"`
	Depth      int      `json:"depth,omitempty"`
	MaxFuzz    int      `json:"max_fuzz,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// RunSummary represents high-level metadata for a single audit run.
type RunSummary struct {
	ID        string `json:"id"`
	Target    string `json:"target"`
	Dir       string `json:"dir"`
	CreatedAt string `json:"created_at"`
}

// New creates a new Server instance.
func New(cfg Config) (*Server, error) {
	if cfg.RunsDir == "" {
		cfg.RunsDir = filepath.Join(".scoutr", "runs")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}

	dist, err := web.DistFS()
	if err != nil {
		return nil, fmt.Errorf("load embedded web assets: %w", err)
	}

	triageRunner := cfg.TriageRunner
	if triageRunner == nil {
		triageRunner = triage.Run
	}

	runner := cfg.Runner
	if runner == nil {
		runner = tools.NewExecRunner()
	}

	s := &Server{
		cfg:          cfg,
		distFS:       dist,
		triageRunner: triageRunner,
		runner:       runner,
	}

	return s, nil
}

// Addr returns the bound server address or configured address.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.Addr
}

// URL returns the full HTTP URL for the server.
func (s *Server) URL() string {
	addr := s.Addr()
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return "http://" + addr
}

// Start begins listening and serving HTTP requests.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Addr, err)
	}
	s.listener = ln
	s.httpServer = &http.Server{
		Handler: s.Routes(),
	}

	go func() {
		_ = s.httpServer.Serve(ln)
	}()

	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Routes registers the API endpoints and SPA file server.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/scope", s.handleScope)
	mux.HandleFunc("/api/runs", s.handleRuns)
	mux.HandleFunc("/api/runs/", s.handleRunArtifacts)
	mux.HandleFunc("/api/scan", s.handleStartScan)
	mux.HandleFunc("/api/scan/status", s.handleScanStatus)
	mux.HandleFunc("/api/scan/cancel", s.handleScanCancel)
	mux.HandleFunc("/api/tools", s.handleTools)
	mux.HandleFunc("/api/llm/providers", s.handleLLMProviders)
	mux.HandleFunc("/api/llm/test", s.handleLLMTest)

	// Static SPA router
	mux.HandleFunc("/", s.handleSPA)

	return mux
}

// handleScope returns the active scope YAML configuration.
func (s *Server) handleScope(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cfg.ScopeFile == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"in_scope":     []string{},
			"out_of_scope": []string{},
			"loaded":       false,
		})
		return
	}

	sc, err := scope.LoadFromFile(s.cfg.ScopeFile)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"in_scope":     []string{},
			"out_of_scope": []string{},
			"error":        err.Error(),
			"loaded":       false,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"in_scope":     sc.InScope,
		"out_of_scope": sc.OutOfScope,
		"file":         s.cfg.ScopeFile,
		"loaded":       true,
	})
}

// handleRuns lists all available workspace run directories.
func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := os.ReadDir(s.cfg.RunsDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []RunSummary{})
			return
		}
		http.Error(w, fmt.Sprintf("read runs directory: %v", err), http.StatusInternalServerError)
		return
	}

	var runs []RunSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		runID := e.Name()
		runPath := filepath.Join(s.cfg.RunsDir, runID)

		target := runID
		if idx := strings.Index(runID, "-"); idx != -1 {
			target = runID[:idx]
		}

		info, _ := e.Info()
		createdAt := ""
		if info != nil {
			createdAt = info.ModTime().Format("2006-01-02 15:04:05")
		}

		runs = append(runs, RunSummary{
			ID:        runID,
			Target:    target,
			Dir:       runPath,
			CreatedAt: createdAt,
		})
	}

	// Sort runs descending by ID (which starts with target-timestamp)
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].ID > runs[j].ID
	})

	writeJSON(w, http.StatusOK, runs)
}

// handleRunArtifacts routes requests for artifacts within a specific run.
func (s *Server) handleRunArtifacts(w http.ResponseWriter, r *http.Request) {
	// Pattern: /api/runs/{runID}/{artifact}[/{sub...}]
	path := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "run ID is required", http.StatusBadRequest)
		return
	}

	runID := parts[0]
	if strings.Contains(runID, "..") || strings.ContainsAny(runID, `/\`) {
		http.Error(w, "invalid run ID", http.StatusBadRequest)
		return
	}

	runPath := filepath.Join(s.cfg.RunsDir, runID)
	ws, err := workspace.OpenRun(runPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("run not found: %v", err), http.StatusNotFound)
		return
	}

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Run summary
		writeJSON(w, http.StatusOK, map[string]any{
			"id":     runID,
			"dir":    runPath,
			"target": filepath.Base(runPath),
		})
		return
	}

	artifact := parts[1]

	// Handle POST actions for runs (e.g. interactive Tier 2 AI Triage or modular tool runs)
	if r.Method == http.MethodPost {
		if artifact == "triage" {
			s.handleRunTriage(w, r, ws)
			return
		}
		if artifact == "tools" && len(parts) >= 3 && parts[2] != "" {
			s.handleRunTool(w, r, ws, parts[2])
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch artifact {
	case "inventory":
		list, err := ws.LoadInventory()
		if err != nil {
			writeJSON(w, http.StatusOK, []string{})
			return
		}
		writeJSON(w, http.StatusOK, list)

	case "ports":
		var ports []any
		_ = ws.LoadArtifact(workspace.PortsFile, &ports)
		writeJSON(w, http.StatusOK, ports)

	case "httpx":
		var live []any
		_ = ws.LoadArtifact(workspace.HTTPXFile, &live)
		writeJSON(w, http.StatusOK, live)

	case "crawl":
		var crawl []any
		_ = ws.LoadArtifact(workspace.CrawlFile, &crawl)
		writeJSON(w, http.StatusOK, crawl)

	case "fuzz":
		var fuzz []any
		_ = ws.LoadArtifact(workspace.FuzzFile, &fuzz)
		writeJSON(w, http.StatusOK, fuzz)

	case "raw_findings":
		raw, err := ws.LoadRawFindings()
		if err != nil {
			writeJSON(w, http.StatusOK, []*findings.Finding{})
			return
		}
		writeJSON(w, http.StatusOK, raw)

	case "findings":
		vf, err := ws.LoadValidatedFindings()
		if err != nil {
			writeJSON(w, http.StatusOK, []*validate.ValidatedFinding{})
			return
		}
		writeJSON(w, http.StatusOK, vf)

	case "triage":
		var tr any
		if err := ws.LoadArtifact(workspace.TriageFile, &tr); err != nil {
			writeJSON(w, http.StatusOK, nil)
			return
		}
		writeJSON(w, http.StatusOK, tr)

	case "submission_ready":
		var sub any
		if err := ws.LoadArtifact(workspace.SubmissionQueueFile, &sub); err != nil {
			writeJSON(w, http.StatusOK, nil)
			return
		}
		writeJSON(w, http.StatusOK, sub)

	case "drafts":
		if len(parts) >= 3 && parts[2] != "" {
			draftName := parts[2]
			p, err := ws.DraftPath(draftName)
			if err != nil {
				http.Error(w, "invalid draft path", http.StatusBadRequest)
				return
			}
			content, err := os.ReadFile(p)
			if err != nil {
				http.Error(w, "draft not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(content)
			return
		}

		drafts, err := ws.ListDrafts()
		if err != nil {
			writeJSON(w, http.StatusOK, []string{})
			return
		}
		writeJSON(w, http.StatusOK, drafts)

	case "report":
		format := r.URL.Query().Get("format")
		fileName := workspace.ReportMDFile
		contentType := "text/markdown; charset=utf-8"
		if format == "html" {
			fileName = workspace.ReportHTMLFile
			contentType = "text/html; charset=utf-8"
		}
		p := filepath.Join(ws.Dir, fileName)
		content, err := os.ReadFile(p)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s not found", fileName), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(content)

	default:
		http.Error(w, fmt.Sprintf("unknown artifact: %s", artifact), http.StatusNotFound)
	}
}

// handleSPA serves the static frontend assets and provides SPA routing fallback.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	// Trim leading slash
	cleanPath := strings.TrimPrefix(filepath.Clean(r.URL.Path), string(filepath.Separator))
	if cleanPath == "" || cleanPath == "." {
		cleanPath = "index.html"
	}

	// Try reading file from embedded filesystem
	file, err := s.distFS.Open(cleanPath)
	if err != nil {
		// SPA fallback: return index.html for client-side routing
		indexFile, ierr := s.distFS.Open("index.html")
		if ierr != nil {
			http.Error(w, "dashboard assets not built. Run 'npm run build' in web/", http.StatusNotFound)
			return
		}
		defer indexFile.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.Copy(w, indexFile)
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil || stat.IsDir() {
		// Directories also fall back to index.html
		indexFile, ierr := s.distFS.Open("index.html")
		if ierr != nil {
			http.Error(w, "dashboard assets not built", http.StatusNotFound)
			return
		}
		defer indexFile.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.Copy(w, indexFile)
		return
	}

	// Content type by extension
	switch filepath.Ext(cleanPath) {
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	}

	_, _ = io.Copy(w, file)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// RunTriageRequest defines the payload for triggering AI triage from the dashboard.
type RunTriageRequest struct {
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
}

func (s *Server) handleRunTriage(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var req RunTriageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	model := strings.TrimSpace(req.Model)
	if model == "" {
		http.Error(w, "model name is required for AI triage", http.StatusBadRequest)
		return
	}

	list, err := ws.LoadValidatedFindings()
	if err != nil {
		http.Error(w, fmt.Sprintf("load validated findings: %v", err), http.StatusInternalServerError)
		return
	}
	if len(list) == 0 {
		http.Error(w, "no validated findings available to triage (validate stage must run first)", http.StatusBadRequest)
		return
	}

	client, err := triage.NewClient(req.Provider, req.Endpoint, model, 120*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("initialize LLM client: %v", err), http.StatusBadRequest)
		return
	}

	techMap := loadTechMapFromWorkspace(ws)

	opts := triage.Options{
		Client:    client,
		Model:     model,
		BatchSize: triage.DefaultBatchSize,
	}

	runner := s.triageRunner
	if runner == nil {
		runner = triage.Run
	}

	report, err := runner(r.Context(), list, techMap, opts)
	if err != nil {
		http.Error(w, fmt.Sprintf("triage execution failed: %v", err), http.StatusInternalServerError)
		return
	}

	if err := ws.SaveArtifact(workspace.TriageFile, report); err != nil {
		http.Error(w, fmt.Sprintf("save triage artifact: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func loadTechMapFromWorkspace(ws *workspace.Workspace) map[string][]string {
	if ws == nil {
		return nil
	}
	var results []struct {
		Host         string   `json:"host"`
		Technologies []string `json:"technologies"`
	}
	if err := ws.LoadArtifact(workspace.HTTPXFile, &results); err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, r := range results {
		if r.Host != "" && len(r.Technologies) > 0 {
			out[strings.ToLower(r.Host)] = r.Technologies
		}
	}
	return out
}

// handleLLMProviders returns metadata and default endpoints for supported providers.
func (s *Server) handleLLMProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providers := []map[string]any{
		{
			"id":               "lmstudio",
			"name":             "LM Studio",
			"default_endpoint": triage.DefaultLMStudioEndpoint,
			"description":      "Local OpenAI-compatible inference with LM Studio",
			"suggested_models": []string{"llama-3.2-3b-instruct", "qwen2.5-coder-7b-instruct", "mistral-7b-instruct-v0.3"},
		},
		{
			"id":               "llamacpp",
			"name":             "llama.cpp",
			"default_endpoint": triage.DefaultLlamaCppEndpoint,
			"description":      "High-throughput local C++ inference via llama.cpp server",
			"suggested_models": []string{"qwen2.5-coder-7b", "llama-3.2-3b", "mistral-7b"},
		},
		{
			"id":               "ollama",
			"name":             "Ollama",
			"default_endpoint": triage.DefaultOllamaEndpoint,
			"description":      "Local daemon for open-weights models",
			"suggested_models": []string{"llama3.2", "qwen2.5-coder:7b", "mistral"},
		},
		{
			"id":               "openai",
			"name":             "OpenAI / Custom",
			"default_endpoint": triage.DefaultOpenAIEndpoint,
			"description":      "Any remote or custom OpenAI-compatible completions endpoint",
			"suggested_models": []string{"gpt-4o", "gpt-4o-mini"},
		},
	}

	writeJSON(w, http.StatusOK, providers)
}

// LLMTestRequest defines parameters to test connectivity to an LLM provider.
type LLMTestRequest struct {
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
}

// LLMTestResponse is returned when probing an LLM endpoint.
type LLMTestResponse struct {
	OK       bool     `json:"ok"`
	Endpoint string   `json:"endpoint"`
	Models   []string `json:"models,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// handleLLMTest probes an LLM endpoint to verify connectivity and discover loaded models.
func (s *Server) handleLLMTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LLMTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeJSON(w, http.StatusOK, LLMTestResponse{
			OK:    false,
			Error: fmt.Sprintf("invalid request payload: %v", err),
		})
		return
	}

	endpoint := strings.TrimSpace(req.Endpoint)
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if endpoint == "" {
		switch provider {
		case "lmstudio", "lm-studio":
			endpoint = triage.DefaultLMStudioEndpoint
		case "llamacpp", "llama.cpp":
			endpoint = triage.DefaultLlamaCppEndpoint
		case "openai":
			endpoint = triage.DefaultOpenAIEndpoint
		default:
			endpoint = triage.DefaultOllamaEndpoint
		}
	}

	client := &http.Client{
		Timeout: 4 * time.Second,
	}

	var checkURL string
	switch provider {
	case "ollama":
		checkURL = strings.TrimRight(endpoint, "/") + "/api/tags"
	default:
		if strings.HasSuffix(endpoint, "/v1") {
			checkURL = endpoint + "/models"
		} else {
			checkURL = strings.TrimRight(endpoint, "/") + "/v1/models"
		}
	}

	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, checkURL, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, LLMTestResponse{
			OK:       false,
			Endpoint: endpoint,
			Error:    err.Error(),
		})
		return
	}

	if apiKey := os.Getenv(triage.APIKeyEnv); apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		writeJSON(w, http.StatusOK, LLMTestResponse{
			OK:       false,
			Endpoint: endpoint,
			Error:    fmt.Sprintf("connection refused or timeout at %s: %v", endpoint, err),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeJSON(w, http.StatusOK, LLMTestResponse{
			OK:       false,
			Endpoint: endpoint,
			Error:    fmt.Sprintf("endpoint %s returned HTTP status %d", checkURL, resp.StatusCode),
		})
		return
	}

	var modelNames []string
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if provider == "ollama" {
		var oResp struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		if err := json.Unmarshal(raw, &oResp); err == nil {
			for _, m := range oResp.Models {
				if m.Name != "" {
					modelNames = append(modelNames, m.Name)
				}
			}
		}
	} else {
		var cResp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &cResp); err == nil {
			for _, m := range cResp.Data {
				if m.ID != "" {
					modelNames = append(modelNames, m.ID)
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, LLMTestResponse{
		OK:       true,
		Endpoint: endpoint,
		Models:   modelNames,
	})
}

// handleStartScan initiates a full or custom security scan in the background.
func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StartScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	target := strings.TrimSpace(req.Target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimRight(target, "/")
	if target == "" {
		http.Error(w, "target domain or hostname is required", http.StatusBadRequest)
		return
	}

	inScope := req.InScope
	if len(inScope) == 0 {
		if s.cfg.ScopeFile != "" {
			if sc, err := scope.LoadFromFile(s.cfg.ScopeFile); err == nil && len(sc.InScope) > 0 {
				inScope = sc.InScope
			}
		}
	}
	if len(inScope) == 0 {
		inScope = []string{target, "*." + target}
	}

	sc := scope.New(inScope, req.OutOfScope)

	s.scanMu.Lock()
	if s.scanStatus.Running {
		s.scanMu.Unlock()
		http.Error(w, "a scan is already in progress", http.StatusConflict)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.scanCancel = cancel
	s.scanStatus = ScanStatus{
		Running:     true,
		Target:      target,
		StageIndex:  0,
		TotalStages: 8,
		StageName:   "starting",
		Detail:      fmt.Sprintf("Initializing scan pipeline for %s...", target),
		Logs:        []string{fmt.Sprintf("[%s] Initializing security scan for target: %s", time.Now().Format("15:04:05"), target)},
		StartTime:   time.Now().Format("2006-01-02 15:04:05"),
	}
	s.scanMu.Unlock()

	go func() {
		defer cancel()
		logFunc := func(format string, args ...any) {
			line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
			s.scanMu.Lock()
			s.scanStatus.Logs = append(s.scanStatus.Logs, line)
			if len(s.scanStatus.Logs) > 1000 {
				s.scanStatus.Logs = s.scanStatus.Logs[len(s.scanStatus.Logs)-1000:]
			}
			s.scanMu.Unlock()
		}
		progFunc := func(stage int, stageName string, detail string) {
			s.scanMu.Lock()
			s.scanStatus.StageIndex = stage
			s.scanStatus.StageName = stageName
			s.scanStatus.Detail = detail
			s.scanMu.Unlock()
		}

		opts := pipeline.Options{
			Scope:       sc,
			Target:      target,
			RunsDir:     s.cfg.RunsDir,
			SkipPorts:   req.SkipPorts || (req.ScanMode == "passive"),
			SkipCrawl:   req.SkipCrawl || (req.ScanMode == "passive"),
			SkipFuzz:    req.SkipFuzz || (req.ScanMode == "passive"),
			SkipXSS:     req.SkipXSS || (req.ScanMode == "passive"),
			SkipNuclei:  req.SkipNuclei || (req.ScanMode == "passive"),
			External:    true,
			PassiveOnly: req.ScanMode == "passive",
			Rate:        req.RateLimit,
			DryRun:      req.DryRun,
			Runner:      s.runner,
			Log:         logFunc,
			OnProgress:  progFunc,
		}

		res, runErr := pipeline.Run(ctx, opts)
		s.scanMu.Lock()
		s.scanStatus.Running = false
		s.scanStatus.EndTime = time.Now().Format("2006-01-02 15:04:05")
		if runErr != nil {
			s.scanStatus.Error = runErr.Error()
			s.scanStatus.Detail = "Scan stopped: " + runErr.Error()
			s.scanStatus.Logs = append(s.scanStatus.Logs, fmt.Sprintf("[%s] Scan ERROR: %v", time.Now().Format("15:04:05"), runErr))
		} else if res != nil && res.Workspace != nil {
			s.scanStatus.RunID = filepath.Base(res.Workspace.Dir)
			s.scanStatus.Detail = res.Summary
			s.scanStatus.Logs = append(s.scanStatus.Logs, fmt.Sprintf("[%s] Scan finished successfully. Workspace run: %s", time.Now().Format("15:04:05"), s.scanStatus.RunID))
		}
		s.scanMu.Unlock()
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "started",
		"target": target,
	})
}

// handleScanStatus returns current scan progress, stages, and recent execution logs.
func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.scanMu.RLock()
	status := s.scanStatus
	s.scanMu.RUnlock()

	writeJSON(w, http.StatusOK, status)
}

// handleScanCancel terminates the currently running security scan.
func (s *Server) handleScanCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.scanMu.Lock()
	if s.scanStatus.Running && s.scanCancel != nil {
		s.scanCancel()
		s.scanStatus.Running = false
		s.scanStatus.Detail = "Scan cancelled by user"
		s.scanStatus.Logs = append(s.scanStatus.Logs, fmt.Sprintf("[%s] Scan cancelled by user", time.Now().Format("15:04:05")))
		s.scanMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"status": "cancelled"})
		return
	}
	s.scanMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"status": "not_running"})
}

// handleTools lists installed tools, their status, versions, and installation hints.
func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	statuses := tools.InspectArsenal(r.Context(), s.runner)
	writeJSON(w, http.StatusOK, statuses)
}

// handleRunTool executes an individual tool on an existing workspace run.
func (s *Server) handleRunTool(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, tool string) {
	var req ToolRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	var sc *scope.Scope
	if len(req.InScope) > 0 {
		sc = scope.New(req.InScope, req.OutOfScope)
	} else if s.cfg.ScopeFile != "" {
		sc, _ = scope.LoadFromFile(s.cfg.ScopeFile)
	}
	if sc == nil {
		target := filepath.Base(ws.Dir)
		if idx := strings.Index(target, "-"); idx != -1 {
			target = target[:idx]
		}
		sc = scope.New([]string{target, "*." + target}, nil)
	}

	logFunc := func(format string, args ...any) {}

	tool = strings.ToLower(strings.TrimSpace(tool))
	switch tool {
	case "subdomains", "recon":
		hosts, err := pipeline.RunSubdomainsOnly(r.Context(), ws, sc, s.runner, true, false, req.RateLimit, logFunc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run subdomains: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(hosts), "result": hosts})

	case "ports":
		ports, err := pipeline.RunPortsOnly(r.Context(), ws, sc, s.runner, req.TopPorts, req.RateLimit, false, logFunc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run ports: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(ports), "result": ports})

	case "probe", "httpx":
		live, err := pipeline.RunProbeOnly(r.Context(), ws, sc, s.runner, req.RateLimit, logFunc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run probe: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(live), "result": live})

	case "crawl", "katana":
		crawled, err := pipeline.RunCrawlOnly(r.Context(), ws, sc, s.runner, req.Depth, req.RateLimit, logFunc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run crawl: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(crawled), "result": crawled})

	case "fuzz", "ffuf":
		fuzzed, err := pipeline.RunFuzzOnly(r.Context(), ws, sc, s.runner, req.MaxFuzz, req.RateLimit, logFunc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run fuzz: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(fuzzed), "result": fuzzed})

	case "xss", "dalfox":
		raw, err := pipeline.RunXSSOnly(r.Context(), ws, sc, s.runner, 20, req.RateLimit, logFunc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run xss: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(raw), "result": raw})

	case "nuclei":
		raw, err := pipeline.RunNucleiOnly(r.Context(), ws, sc, s.runner, req.RateLimit, logFunc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run nuclei: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(raw), "result": raw})

	case "validate":
		vf, err := pipeline.RunValidateOnly(r.Context(), ws, sc)
		if err != nil {
			http.Error(w, fmt.Sprintf("run validate: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tool": tool, "status": "success", "count": len(vf), "result": vf})

	default:
		http.Error(w, fmt.Sprintf("unknown tool: %s", tool), http.StatusBadRequest)
	}
}
