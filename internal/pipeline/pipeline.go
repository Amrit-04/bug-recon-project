package pipeline

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/recon/subdomains"
	"github.com/scoutr/scoutr/internal/report"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

// Options configures the full or custom pipeline execution.
type Options struct {
	Scope       *scope.Scope
	Target      string
	RunsDir     string
	TopPorts    int
	Depth       int
	MaxFuzz     int
	SkipPorts   bool
	SkipNmap    bool
	SkipCrawl   bool
	SkipFuzz    bool
	SkipXSS     bool
	SkipNuclei  bool
	External    bool
	PassiveOnly bool
	Rate        int
	RatePerHost int
	DryRun      bool
	Runner      tools.CommandRunner
	Log         func(format string, args ...any)
	OnProgress  func(stage int, stageName string, detail string)
}

// Result holds the final artifacts and metadata of a pipeline execution.
type Result struct {
	Workspace *workspace.Workspace
	Target    string
	Hosts     []string
	Ports     []tools.PortResult
	LiveHTTP  []tools.HTTPXResult
	Crawled   []tools.KatanaResult
	Fuzzed    []tools.FFUFResult
	Endpoints []*endpoints.Endpoint
	Raw       []*findings.Finding
	Validated []*validate.ValidatedFinding
	Summary   string
}

// Run executes the complete Tier 0/1 deterministic pipeline in code-defined sequence.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Scope == nil {
		return nil, fmt.Errorf("scope is required for pipeline execution")
	}

	target := opts.Target
	if target == "" {
		roots := tools.ExtractRootDomains(opts.Scope)
		if len(roots) > 0 {
			target = roots[0]
		} else {
			target = "target"
		}
	}

	if opts.TopPorts <= 0 {
		opts.TopPorts = tools.DefaultNaabuTopPorts
	}
	topPorts := tools.NormalizeTopPorts(opts.TopPorts)

	if opts.Depth <= 0 {
		opts.Depth = 2
	}
	if opts.MaxFuzz <= 0 {
		opts.MaxFuzz = tools.DefaultMaxFFUFTargets
	}
	if opts.Rate <= 0 {
		opts.Rate = 10
	}
	if opts.RatePerHost <= 0 {
		opts.RatePerHost = 3
	}

	logger := opts.Log
	if logger == nil {
		logger = func(string, ...any) {}
	}
	progress := opts.OnProgress
	if progress == nil {
		progress = func(int, string, string) {}
	}

	runner := opts.Runner
	if runner == nil {
		runner = tools.NewExecRunner()
	}

	if opts.DryRun {
		logger("[DRY-RUN] Pipeline target: %s (in_scope: %v)", target, opts.Scope.InScope)
		progress(1, "enum", "Passive subdomains & DNS resolution (dry-run)")
		progress(2, "ports", "naabu & nmap port scanning (dry-run)")
		progress(3, "probe", "httpx service probing (dry-run)")
		progress(4, "crawl", "katana shallow crawl (dry-run)")
		progress(5, "fuzz", "ffuf content discovery (dry-run)")
		progress(6, "xss", "dalfox XSS scan (dry-run)")
		progress(7, "nuclei", "nuclei posture check (dry-run)")
		progress(8, "validate", "7-Check Readiness Gate (dry-run)")
		return &Result{
			Target:  target,
			Summary: "[DRY-RUN] Pipeline simulated successfully without network requests",
		}, nil
	}

	ws, err := workspace.NewRun(opts.RunsDir, target)
	if err != nil {
		return nil, fmt.Errorf("create workspace run: %w", err)
	}

	// Persist the scope.yaml file in the run directory for standalone reproducibility
	_ = ws.SaveArtifact("scope.yaml", opts.Scope)

	// ---- Stage 1: Passive enumeration + DNS resolution -------------------
	progress(1, "enum", "Discovering subdomains and resolving DNS...")
	hostSet := make(map[string]bool)
	addHost := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && opts.Scope.IsInScope(h) {
			hostSet[h] = true
		}
	}

	if !opts.PassiveOnly {
		if hosts, err := subdomains.FromCRTSH(ctx, opts.Scope); err != nil {
			logger("[WARN] crt.sh enumeration failed: %v", err)
		} else {
			for _, h := range hosts {
				addHost(h)
			}
		}
	}
	if opts.External {
		roots := tools.ExtractRootDomains(opts.Scope)
		if hosts, err := tools.RunSubfinder(ctx, runner, opts.Scope, roots, tools.LogFunc(logger)); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
		if hosts, err := tools.RunAmass(ctx, runner, opts.Scope, roots, tools.LogFunc(logger)); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
		if hosts, err := tools.RunAssetfinder(ctx, runner, opts.Scope, roots, tools.LogFunc(logger)); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
	}
	for _, d := range tools.ExtractRootDomains(opts.Scope) {
		addHost(d)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var hosts []string
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no in-scope hosts discovered for target %s", target)
	}

	if resolved, err := tools.RunDNSX(ctx, runner, opts.Scope, hosts, opts.Rate, tools.LogFunc(logger)); err == nil && len(resolved) > 0 {
		var resolvedHosts []string
		for _, r := range resolved {
			resolvedHosts = append(resolvedHosts, r.Host)
		}
		hosts = resolvedHosts
	}

	if err := ws.SaveInventory(hosts); err != nil {
		return nil, fmt.Errorf("save inventory: %w", err)
	}
	logger("[1/8] enum: %d in-scope hosts discovered", len(hosts))

	// ---- Stage 2: Port discovery + Service detection ---------------------
	var ports []tools.PortResult
	if !opts.SkipPorts {
		progress(2, "ports", fmt.Sprintf("Scanning open ports on %d hosts...", len(hosts)))
		ports, err = tools.RunNaabu(ctx, runner, opts.Scope, hosts, topPorts, opts.Rate, tools.LogFunc(logger))
		if err != nil && ctx.Err() == nil {
			logger("[WARN] naabu port scan warning: %v", err)
		}
		if !opts.SkipNmap && len(ports) > 0 {
			services, nmapErr := tools.RunNmapServiceScan(ctx, runner, opts.Scope, tools.NmapTargets(ports), opts.Rate, tools.LogFunc(logger))
			if nmapErr != nil && ctx.Err() == nil {
				logger("[WARN] nmap service scan warning: %v", nmapErr)
			}
			ports = MergeServiceFingerprints(ports, services)
		}
		if err := ws.SaveArtifact(workspace.PortsFile, ports); err != nil {
			return nil, fmt.Errorf("save port artifact: %w", err)
		}
		logger("[2/8] ports: %d open ports discovered", len(ports))
	} else {
		progress(2, "ports", "Skipped by user configuration")
		logger("[2/8] ports: skipped")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ---- Stage 3: HTTP probing -------------------------------------------
	progress(3, "probe", "Probing live HTTP endpoints & web technologies...")
	probeTargets := tools.BuildHTTPXTargets(hosts, ports)
	live, err := tools.RunPDHTTPX(ctx, runner, opts.Scope, probeTargets, opts.Rate, tools.LogFunc(logger))
	if err != nil && ctx.Err() == nil {
		logger("[WARN] httpx warning: %v", err)
	}
	if err := ws.SaveArtifact(workspace.HTTPXFile, live); err != nil {
		return nil, fmt.Errorf("save httpx artifact: %w", err)
	}

	var liveURLs []string
	for _, l := range live {
		liveURLs = append(liveURLs, l.URL)
	}
	if len(liveURLs) == 0 {
		for _, h := range hosts {
			liveURLs = MergeUnique(liveURLs, "https://"+h)
		}
	}
	logger("[3/8] probe: %d live HTTP services responding", len(liveURLs))
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ---- Stage 4: Web Crawling -------------------------------------------
	var discoveredTargets []string
	var crawled []tools.KatanaResult
	if !opts.SkipCrawl {
		progress(4, "crawl", fmt.Sprintf("Crawling %d live websites for pages and links...", len(liveURLs)))
		var crawlErr error
		crawled, crawlErr = tools.RunKatana(ctx, runner, opts.Scope, liveURLs, opts.Rate, opts.Depth, tools.LogFunc(logger))
		if crawlErr != nil && ctx.Err() == nil {
			logger("[WARN] katana crawler warning: %v", crawlErr)
		}
		if err := ws.SaveArtifact(workspace.CrawlFile, crawled); err != nil {
			return nil, fmt.Errorf("save crawl artifact: %w", err)
		}
		for _, c := range crawled {
			discoveredTargets = MergeUnique(discoveredTargets, c.Endpoint)
		}
		logger("[4/8] crawl: %d endpoints mapped", len(discoveredTargets))
	} else {
		progress(4, "crawl", "Skipped by user configuration")
		logger("[4/8] crawl: skipped")
	}
	discoveredTargets = MergeUnique(discoveredTargets, liveURLs...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ---- Stage 5: Curated Content & Directory Discovery -----------------
	var fuzzed []tools.FFUFResult
	var fuzzURLs []string
	if !opts.SkipFuzz {
		progress(5, "fuzz", "Searching for hidden paths, admin portals and files...")
		var fuzzErr error
		fuzzed, fuzzErr = tools.RunFFUF(ctx, runner, opts.Scope, liveURLs, opts.RatePerHost, opts.MaxFuzz, tools.LogFunc(logger))
		if fuzzErr != nil && ctx.Err() == nil {
			logger("[WARN] ffuf fuzzer warning: %v", fuzzErr)
		}
		if err := ws.SaveArtifact(workspace.FuzzFile, fuzzed); err != nil {
			return nil, fmt.Errorf("save fuzz artifact: %w", err)
		}
		for _, f := range fuzzed {
			fuzzURLs = append(fuzzURLs, f.URL)
		}
		logger("[5/8] fuzz: %d candidate paths discovered", len(fuzzURLs))
	} else {
		progress(5, "fuzz", "Skipped by user configuration")
		logger("[5/8] fuzz: skipped")
	}
	discoveredTargets = MergeUnique(discoveredTargets, fuzzURLs...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ---- Phase 2: Central Endpoint Intelligence & Normalization ---------
	endpointInv := endpoints.NewInventory()

	// 1. Ingest historical archive URLs (waybackurls/gau)
	archiveURLs, _ := tools.RunURLs(ctx, runner, opts.Scope, tools.ExtractRootDomains(opts.Scope), tools.LogFunc(logger))
	for _, aURL := range archiveURLs {
		if opts.Scope.IsURLInScope(aURL) {
			endpointInv.AddRawURL(aURL, "GET", "archive", nil)
		}
	}

	// 2. Ingest live HTTP probed services & tech stacks
	for _, l := range live {
		if opts.Scope.IsURLInScope(l.URL) {
			ep, _ := endpointInv.AddRawURL(l.URL, "GET", "httpx", l.Tech)
			if ep != nil {
				ep.ResponseMetadata = &endpoints.ResponseMetadata{
					StatusCode: l.StatusCode,
				}
			}
		}
	}

	// 3. Ingest crawled endpoints
	for _, c := range crawled {
		if opts.Scope.IsURLInScope(c.Endpoint) {
			endpointInv.AddRawURL(c.Endpoint, "GET", "katana", nil)
		}
	}

	// 4. Ingest fuzzed endpoints
	for _, f := range fuzzed {
		if opts.Scope.IsURLInScope(f.URL) {
			ep, _ := endpointInv.AddRawURL(f.URL, "GET", "ffuf", nil)
			if ep != nil {
				ep.ResponseMetadata = &endpoints.ResponseMetadata{
					StatusCode:    f.Status,
					ContentLength: int64(f.Length),
				}
			}
		}
	}

	// 5. Public API Specification Discovery (OpenAPI/Swagger) & JS Extraction
	// Strict scope enforcement via ScopedTransport
	scopeHTTPClient := httpx.New(httpx.Config{
		Scope:       opts.Scope,
		Timeout:     10 * time.Second,
		MaxBodySize: 1024 * 1024,
		GlobalRate:  float64(opts.Rate),
		PerHostRate: float64(opts.RatePerHost),
		DryRun:      opts.DryRun,
		UserAgent:   "scoutr/1.0 (security research)",
	})

	for _, l := range live {
		if opts.Scope.IsURLInScope(l.URL) {
			specEndpoints, _ := endpoints.DiscoverPublicAPISpec(ctx, scopeHTTPClient, l.URL, opts.Scope)
			for _, specEp := range specEndpoints {
				endpointInv.AddOrMerge(specEp)
			}
		}
	}

	// Script JS extraction: scan crawled script URLs (capped at 15 scripts to respect timeouts)
	jsCount := 0
	for _, c := range crawled {
		lowerEp := strings.ToLower(c.Endpoint)
		if strings.HasSuffix(lowerEp, ".js") && opts.Scope.IsURLInScope(c.Endpoint) && jsCount < 15 {
			jsCount++
			if resp, err := scopeHTTPClient.Get(ctx, c.Endpoint); err == nil && resp != nil {
				if resp.StatusCode == 200 {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
					resp.Body.Close()
					jsEndpoints := endpoints.ExtractEndpointsFromJS(string(body), c.Endpoint, opts.Scope)
					for _, jsEp := range jsEndpoints {
						endpointInv.AddOrMerge(jsEp)
					}
				} else {
					resp.Body.Close()
				}
			}
		}
	}

	endpointInv.FilterInScope(opts.Scope)
	allEndpoints := endpointInv.GetAll()
	_ = ws.SaveArtifact(workspace.EndpointsFile, allEndpoints)

	for _, ep := range allEndpoints {
		discoveredTargets = MergeUnique(discoveredTargets, ep.URL)
	}
	logger("[intelligence] %d normalized endpoints stored in %s", len(allEndpoints), workspace.EndpointsFile)

	// ---- Stage 6: Parameterized XSS Probing ------------------------------
	var raw []*findings.Finding
	if !opts.SkipXSS {
		progress(6, "xss", "Testing parameterized inputs for Cross-Site Scripting...")
		xssFindings, xssErr := tools.RunDalfox(ctx, runner, opts.Scope, discoveredTargets, opts.RatePerHost, tools.DefaultMaxDalfoxTargets, tools.LogFunc(logger))
		if xssErr != nil && ctx.Err() == nil {
			logger("[WARN] dalfox warning: %v", xssErr)
		}
		raw = append(raw, xssFindings...)
		logger("[6/8] xss: %d XSS candidate findings", len(xssFindings))
	} else {
		progress(6, "xss", "Skipped by user configuration")
		logger("[6/8] xss: skipped")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ---- Stage 7: Read-Only Nuclei Posture Auditing ----------------------
	if !opts.SkipNuclei {
		progress(7, "nuclei", "Checking safe read-only posture and misconfigurations...")
		nucleiTargets := MergeUnique(append([]string{}, liveURLs...), fuzzURLs...)
		posture, nucleiErr := tools.RunNucleiPosture(ctx, runner, opts.Scope, nucleiTargets, opts.Rate, tools.LogFunc(logger))
		if nucleiErr != nil && ctx.Err() == nil {
			logger("[WARN] nuclei posture warning: %v", nucleiErr)
		}
		raw = append(raw, posture...)
		logger("[7/8] nuclei: %d posture findings", len(posture))
	} else {
		progress(7, "nuclei", "Skipped by user configuration")
		logger("[7/8] nuclei: skipped")
	}

	if err := ws.SaveRawFindings(raw); err != nil {
		return nil, fmt.Errorf("save raw findings: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ---- Stage 8: 7-Check Readiness Gate ---------------------------------
	progress(8, "validate", "Executing deterministic 7-Check Readiness Gate...")
	validator := validate.NewValidator(opts.Scope)
	validated := validator.ValidateAndGroup(ctx, raw)
	if err := ws.SaveValidatedFindings(validated); err != nil {
		return nil, fmt.Errorf("save validated findings: %w", err)
	}

	var verified, manual, suppressed int
	for _, vf := range validated {
		switch vf.Status {
		case validate.StatusVerified:
			verified++
		case validate.StatusNeedsManualReview:
			manual++
		case validate.StatusSuppressed:
			suppressed++
		}
	}
	logger("[8/8] validate: %d verified, %d needs review, %d suppressed", verified, manual, suppressed)

	// Save HTML and Markdown reports
	if len(validated) > 0 {
		_ = ws.SaveReportMD(report.GenerateMarkdown(target, validated))
		_ = ws.SaveReportHTML(report.GenerateHTML(target, validated))
	}

	summary := fmt.Sprintf("Audit complete for %s. Discovered %d hosts, %d live HTTP services. Findings: %d Verified, %d Needs Review, %d Suppressed.",
		target, len(hosts), len(liveURLs), verified, manual, suppressed)
	progress(8, "completed", summary)

	return &Result{
		Workspace: ws,
		Target:    target,
		Hosts:     hosts,
		Ports:     ports,
		LiveHTTP:  live,
		Crawled:   crawled,
		Fuzzed:    fuzzed,
		Endpoints: allEndpoints,
		Raw:       raw,
		Validated: validated,
		Summary:   summary,
	}, nil
}

// Single-tool execution wrappers for running individual stages on demand:

// RunSubdomainsOnly discovers subdomains and resolves DNS for a workspace.
func RunSubdomainsOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope, runner tools.CommandRunner, external, passiveOnly bool, rate int, log tools.LogFunc) ([]string, error) {
	if log == nil {
		log = tools.DefaultLog
	}
	if runner == nil {
		runner = tools.NewExecRunner()
	}
	hostSet := make(map[string]bool)
	addHost := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && s.IsInScope(h) {
			hostSet[h] = true
		}
	}

	if !passiveOnly {
		if hosts, err := subdomains.FromCRTSH(ctx, s); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
	}
	if external {
		roots := tools.ExtractRootDomains(s)
		if hosts, err := tools.RunSubfinder(ctx, runner, s, roots, log); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
		if hosts, err := tools.RunAssetfinder(ctx, runner, s, roots, log); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
	}
	for _, d := range tools.ExtractRootDomains(s) {
		addHost(d)
	}

	var hosts []string
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	if resolved, err := tools.RunDNSX(ctx, runner, s, hosts, rate, log); err == nil && len(resolved) > 0 {
		var resolvedHosts []string
		for _, r := range resolved {
			resolvedHosts = append(resolvedHosts, r.Host)
		}
		hosts = resolvedHosts
	}

	if err := ws.SaveInventory(hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// RunPortsOnly executes naabu and nmap on discovered hosts.
func RunPortsOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope, runner tools.CommandRunner, topPorts, rate int, skipNmap bool, log tools.LogFunc) ([]tools.PortResult, error) {
	if log == nil {
		log = tools.DefaultLog
	}
	if runner == nil {
		runner = tools.NewExecRunner()
	}
	hosts, err := ws.LoadInventory()
	if err != nil || len(hosts) == 0 {
		return nil, fmt.Errorf("no inventory hosts found. Run subdomain discovery first")
	}

	ports, err := tools.RunNaabu(ctx, runner, s, hosts, topPorts, rate, log)
	if err != nil {
		return nil, err
	}

	if !skipNmap && len(ports) > 0 {
		services, _ := tools.RunNmapServiceScan(ctx, runner, s, tools.NmapTargets(ports), rate, log)
		ports = MergeServiceFingerprints(ports, services)
	}

	if err := ws.SaveArtifact(workspace.PortsFile, ports); err != nil {
		return nil, err
	}
	return ports, nil
}

// RunProbeOnly executes httpx over hosts and ports.
func RunProbeOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope, runner tools.CommandRunner, rate int, log tools.LogFunc) ([]tools.HTTPXResult, error) {
	if log == nil {
		log = tools.DefaultLog
	}
	if runner == nil {
		runner = tools.NewExecRunner()
	}
	hosts, _ := ws.LoadInventory()
	if len(hosts) == 0 {
		hosts = tools.ExtractRootDomains(s)
	}

	var ports []tools.PortResult
	_ = ws.LoadArtifact(workspace.PortsFile, &ports)

	targets := tools.BuildHTTPXTargets(hosts, ports)
	live, err := tools.RunPDHTTPX(ctx, runner, s, targets, rate, log)
	if err != nil {
		return nil, err
	}

	if err := ws.SaveArtifact(workspace.HTTPXFile, live); err != nil {
		return nil, err
	}
	return live, nil
}

// RunCrawlOnly executes katana crawler over live URLs.
func RunCrawlOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope, runner tools.CommandRunner, depth, rate int, log tools.LogFunc) ([]tools.KatanaResult, error) {
	if log == nil {
		log = tools.DefaultLog
	}
	if runner == nil {
		runner = tools.NewExecRunner()
	}
	liveURLs := loadLiveURLs(ws, s)
	if len(liveURLs) == 0 {
		return nil, fmt.Errorf("no live HTTP targets found. Run probe first")
	}

	crawled, err := tools.RunKatana(ctx, runner, s, liveURLs, rate, depth, log)
	if err != nil {
		return nil, err
	}

	if err := ws.SaveArtifact(workspace.CrawlFile, crawled); err != nil {
		return nil, err
	}
	return crawled, nil
}

// RunFuzzOnly executes ffuf directory search over live URLs.
func RunFuzzOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope, runner tools.CommandRunner, maxTargets, ratePerHost int, log tools.LogFunc) ([]tools.FFUFResult, error) {
	if log == nil {
		log = tools.DefaultLog
	}
	if runner == nil {
		runner = tools.NewExecRunner()
	}
	liveURLs := loadLiveURLs(ws, s)
	if len(liveURLs) == 0 {
		return nil, fmt.Errorf("no live HTTP targets found. Run probe first")
	}

	fuzzed, err := tools.RunFFUF(ctx, runner, s, liveURLs, ratePerHost, maxTargets, log)
	if err != nil {
		return nil, err
	}

	if err := ws.SaveArtifact(workspace.FuzzFile, fuzzed); err != nil {
		return nil, err
	}
	return fuzzed, nil
}

// RunXSSOnly executes dalfox on endpoints and appends findings to raw_findings.json.
func RunXSSOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope, runner tools.CommandRunner, maxTargets, ratePerHost int, log tools.LogFunc) ([]*findings.Finding, error) {
	if log == nil {
		log = tools.DefaultLog
	}
	if runner == nil {
		runner = tools.NewExecRunner()
	}
	endpoints := loadAllEndpoints(ws, s)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints discovered. Run crawl or probe first")
	}

	xssFindings, err := tools.RunDalfox(ctx, runner, s, endpoints, ratePerHost, maxTargets, log)
	if err != nil {
		return nil, err
	}

	raw, _ := ws.LoadRawFindings()
	raw = append(raw, xssFindings...)
	if err := ws.SaveRawFindings(raw); err != nil {
		return nil, err
	}
	return xssFindings, nil
}

// RunNucleiOnly executes read-only posture templates and appends findings to raw_findings.json.
func RunNucleiOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope, runner tools.CommandRunner, rate int, log tools.LogFunc) ([]*findings.Finding, error) {
	if log == nil {
		log = tools.DefaultLog
	}
	if runner == nil {
		runner = tools.NewExecRunner()
	}
	endpoints := loadAllEndpoints(ws, s)
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no targets found. Run probe first")
	}

	posture, err := tools.RunNucleiPosture(ctx, runner, s, endpoints, rate, log)
	if err != nil {
		return nil, err
	}

	raw, _ := ws.LoadRawFindings()
	raw = append(raw, posture...)
	if err := ws.SaveRawFindings(raw); err != nil {
		return nil, err
	}
	return posture, nil
}

// RunValidateOnly runs the 7-Check Readiness Gate on all raw findings.
func RunValidateOnly(ctx context.Context, ws *workspace.Workspace, s *scope.Scope) ([]*validate.ValidatedFinding, error) {
	raw, err := ws.LoadRawFindings()
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("no raw findings in workspace to validate")
	}

	validator := validate.NewValidator(s)
	validated := validator.ValidateAndGroup(ctx, raw)
	if err := ws.SaveValidatedFindings(validated); err != nil {
		return nil, err
	}

	target := ws.Target
	if target == "" {
		target = "target"
	}
	_ = ws.SaveReportMD(report.GenerateMarkdown(target, validated))
	_ = ws.SaveReportHTML(report.GenerateHTML(target, validated))

	return validated, nil
}

// Helper functions:

func loadLiveURLs(ws *workspace.Workspace, s *scope.Scope) []string {
	var live []tools.HTTPXResult
	_ = ws.LoadArtifact(workspace.HTTPXFile, &live)
	var urls []string
	for _, l := range live {
		if l.URL != "" {
			urls = append(urls, l.URL)
		}
	}
	if len(urls) == 0 {
		hosts, _ := ws.LoadInventory()
		for _, h := range hosts {
			urls = MergeUnique(urls, "https://"+h)
		}
	}
	return urls
}

func loadAllEndpoints(ws *workspace.Workspace, s *scope.Scope) []string {
	urls := loadLiveURLs(ws, s)
	var crawled []tools.KatanaResult
	_ = ws.LoadArtifact(workspace.CrawlFile, &crawled)
	for _, c := range crawled {
		if c.Endpoint != "" {
			urls = MergeUnique(urls, c.Endpoint)
		}
	}
	var fuzzed []tools.FFUFResult
	_ = ws.LoadArtifact(workspace.FuzzFile, &fuzzed)
	for _, f := range fuzzed {
		if f.URL != "" {
			urls = MergeUnique(urls, f.URL)
		}
	}
	return urls
}

// MergeUnique appends items avoiding duplicates, preserving order.
func MergeUnique(existing []string, more ...string) []string {
	seen := make(map[string]bool, len(existing)+len(more))
	var out []string
	for _, s := range existing {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range more {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// MergeServiceFingerprints folds nmap -sV results into naabu port list.
func MergeServiceFingerprints(ports, services []tools.PortResult) []tools.PortResult {
	type key struct {
		host string
		port int
	}
	index := make(map[key]int, len(ports))
	for i, p := range ports {
		index[key{p.Host, p.Port}] = i
	}

	for _, svc := range services {
		k := key{svc.Host, svc.Port}
		i, ok := index[k]
		if !ok {
			continue
		}
		ports[i].Service = svc.Service
		ports[i].Product = svc.Product
		ports[i].Version = svc.Version
		if ports[i].IP == "" {
			ports[i].IP = svc.IP
		}
	}
	return ports
}
