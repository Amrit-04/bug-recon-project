package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/recon/subdomains"
	"github.com/scoutr/scoutr/internal/report"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	runTopPorts   int
	runDepth      int
	runMaxFuzz    int
	runSkipPorts  bool
	runSkipNmap   bool
	runSkipCrawl  bool
	runSkipFuzz   bool
	runSkipXSS    bool
	runSkipNuclei bool
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the deterministic Tier 0/1 pipeline with workspace persistence",
	Long: `Run the full deterministic scoutr pipeline in a fixed, code-defined order:

  1. enum    passive subdomains (crt.sh, optional --external tools) + dnsx resolution
  2. ports   naabu (top 100 ports) then nmap -sV on exactly those ports
  3. probe   httpx over hosts enriched with the discovered ports
  4. crawl   katana shallow, scope-constrained link discovery
  5. fuzz    ffuf curated path discovery (candidates only)
  6. xss     dalfox --deep-domxss on parameterised endpoints (candidates only)
  7. nuclei  read-only posture templates
  8. validate the 7-Check Readiness Gate, then persist artifacts

The pipeline sequence is code. No model, flag or config can reorder stages or
choose targets: every stage reads only in-scope artifacts from the workspace.

Tier 2 (triage/drafting) and Tier 3 (submission) are intentionally NOT part of
this command; run them explicitly afterwards:

  scoutr triage --from <run-dir>
  scoutr report --draft --from <run-dir>
  scoutr submit --require-approval --from <run-dir>
`,
	Example: `  scoutr run --scope scope.yaml
  scoutr run --scope scope.yaml --external --top-ports 1000
  scoutr run --scope scope.yaml --skip-xss --skip-nuclei`,
	RunE: runPipeline,
}

func init() {
	runCmd.Flags().BoolVar(&globalConfig.External, "external", false,
		"Merge results from external passive tools (subfinder, amass, assetfinder, dnsx)")
	runCmd.Flags().IntVar(&runTopPorts, "top-ports", tools.DefaultNaabuTopPorts, "naabu port budget: 100 (default) or 1000")
	runCmd.Flags().IntVar(&runDepth, "depth", 2, "katana maximum crawl depth")
	runCmd.Flags().IntVar(&runMaxFuzz, "max-fuzz-targets", tools.DefaultMaxFFUFTargets, "Maximum hosts for ffuf content discovery")
	runCmd.Flags().BoolVar(&runSkipPorts, "skip-ports", false, "Skip naabu/nmap port discovery")
	runCmd.Flags().BoolVar(&runSkipNmap, "skip-nmap", false, "Skip nmap service detection")
	runCmd.Flags().BoolVar(&runSkipCrawl, "skip-crawl", false, "Skip katana crawling")
	runCmd.Flags().BoolVar(&runSkipFuzz, "skip-fuzz", false, "Skip ffuf content discovery")
	runCmd.Flags().BoolVar(&runSkipXSS, "skip-xss", false, "Skip dalfox XSS probing")
	runCmd.Flags().BoolVar(&runSkipNuclei, "skip-nuclei", false, "Skip read-only nuclei posture templates")
}

func runPipeline(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	ctx := cmd.Context()

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}
	s, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	target := scopeTargetLabel(s)
	topPorts := tools.NormalizeTopPorts(runTopPorts)

	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s (in_scope: %v)\n", cfg.ScopeFile, s.InScope)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Pipeline target: %s\n", target)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Stages: enum -> dnsx")
		if !runSkipPorts {
			fmt.Fprintf(os.Stderr, " -> naabu(top %d)", topPorts)
			if !runSkipNmap {
				fmt.Fprintf(os.Stderr, " -> nmap -sV")
			}
		}
		fmt.Fprintf(os.Stderr, " -> httpx")
		if !runSkipCrawl {
			fmt.Fprintf(os.Stderr, " -> katana(depth %d)", runDepth)
		}
		if !runSkipFuzz {
			fmt.Fprintf(os.Stderr, " -> ffuf(cap %d)", runMaxFuzz)
		}
		if !runSkipXSS {
			fmt.Fprintf(os.Stderr, " -> dalfox")
		}
		if !runSkipNuclei {
			fmt.Fprintf(os.Stderr, " -> nuclei(read-only)")
		}
		fmt.Fprintf(os.Stderr, " -> validate(7-check)\n")
		return nil
	}

	ws, err := workspace.NewRun("", target)
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	fmt.Printf("Workspace: %s\n", ws.Dir)

	runner := tools.NewExecRunner()
	logger := loggerFor(cfg.Verbose)
	rate := int(cfg.Rate)
	ratePerHost := int(cfg.RatePerHost)

	// ---- Stage 1: passive enumeration + DNS resolution -------------------
	hostSet := make(map[string]bool)
	addHost := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && s.IsInScope(h) {
			hostSet[h] = true
		}
	}

	if !cfg.PassiveOnly {
		if hosts, err := subdomains.FromCRTSH(ctx, s); err != nil {
			logger("[WARN] crt.sh enumeration failed: %v", err)
		} else {
			for _, h := range hosts {
				addHost(h)
			}
		}
	}
	if cfg.External {
		roots := tools.ExtractRootDomains(s)
		if hosts, err := tools.RunSubfinder(ctx, runner, s, roots, logger); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
		if hosts, err := tools.RunAmass(ctx, runner, s, roots, logger); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
		if hosts, err := tools.RunAssetfinder(ctx, runner, s, roots, logger); err == nil {
			for _, h := range hosts {
				addHost(h)
			}
		}
	}
	// Root domains from the scope file always seed the inventory.
	for _, d := range tools.ExtractRootDomains(s) {
		addHost(d)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	var hosts []string
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no in-scope hosts discovered")
	}

	if resolved, err := tools.RunDNSX(ctx, runner, s, hosts, rate, logger); err == nil && len(resolved) > 0 {
		var resolvedHosts []string
		for _, r := range resolved {
			resolvedHosts = append(resolvedHosts, r.Host)
		}
		hosts = resolvedHosts
	}

	if err := ws.SaveInventory(hosts); err != nil {
		return fmt.Errorf("save inventory: %w", err)
	}
	fmt.Printf("[1/8] enum   : %d in-scope hosts\n", len(hosts))

	// ---- Stage 2: port discovery + service detection ---------------------
	var ports []tools.PortResult
	if !runSkipPorts {
		ports, err = tools.RunNaabu(ctx, runner, s, hosts, topPorts, rate, logger)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Warning: naabu failed: %v\n", err)
		}
		if !runSkipNmap && len(ports) > 0 {
			services, nmapErr := tools.RunNmapServiceScan(ctx, runner, s, tools.NmapTargets(ports), rate, logger)
			if nmapErr != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "Warning: nmap failed: %v\n", nmapErr)
			}
			ports = mergeServiceFingerprints(ports, services)
		}
		if err := ws.SaveArtifact(workspace.PortsFile, ports); err != nil {
			return fmt.Errorf("save port artifact: %w", err)
		}
		fmt.Printf("[2/8] ports  : %d open ports\n", len(ports))
	} else {
		fmt.Println("[2/8] ports  : skipped")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// ---- Stage 3: HTTP probing (ports fed into httpx) --------------------
	probeTargets := tools.BuildHTTPXTargets(hosts, ports)
	live, err := tools.RunPDHTTPX(ctx, runner, s, probeTargets, rate, logger)
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Warning: httpx failed: %v\n", err)
	}
	if err := ws.SaveArtifact(workspace.HTTPXFile, live); err != nil {
		return fmt.Errorf("save httpx artifact: %w", err)
	}

	var liveURLs []string
	for _, l := range live {
		liveURLs = append(liveURLs, l.URL)
	}
	if len(liveURLs) == 0 {
		// Nothing responded: fall back to HTTPS roots so later stages still run.
		for _, h := range hosts {
			liveURLs = mergeUnique(liveURLs, "https://"+h)
		}
	}
	fmt.Printf("[3/8] probe  : %d live HTTP endpoints\n", len(liveURLs))
	if err := ctx.Err(); err != nil {
		return err
	}

	// ---- Stage 4: shallow crawling --------------------------------------
	var endpoints []string
	if !runSkipCrawl {
		crawled, crawlErr := tools.RunKatana(ctx, runner, s, liveURLs, rate, runDepth, logger)
		if crawlErr != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Warning: katana failed: %v\n", crawlErr)
		}
		if err := ws.SaveArtifact(workspace.CrawlFile, crawled); err != nil {
			return fmt.Errorf("save crawl artifact: %w", err)
		}
		for _, c := range crawled {
			endpoints = mergeUnique(endpoints, c.Endpoint)
		}
		fmt.Printf("[4/8] crawl  : %d endpoints\n", len(endpoints))
	} else {
		fmt.Println("[4/8] crawl  : skipped")
	}
	endpoints = mergeUnique(endpoints, liveURLs...)

	// ---- Stage 5: curated content discovery ------------------------------
	var fuzzURLs []string
	if !runSkipFuzz {
		fuzzed, fuzzErr := tools.RunFFUF(ctx, runner, s, liveURLs, ratePerHost, runMaxFuzz, logger)
		if fuzzErr != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Warning: ffuf failed: %v\n", fuzzErr)
		}
		if err := ws.SaveArtifact(workspace.FuzzFile, fuzzed); err != nil {
			return fmt.Errorf("save fuzz artifact: %w", err)
		}
		for _, f := range fuzzed {
			fuzzURLs = append(fuzzURLs, f.URL)
		}
		fmt.Printf("[5/8] fuzz   : %d candidate paths\n", len(fuzzURLs))
	} else {
		fmt.Println("[5/8] fuzz   : skipped")
	}
	endpoints = mergeUnique(endpoints, fuzzURLs...)
	if err := ctx.Err(); err != nil {
		return err
	}

	// ---- Stage 6: XSS candidates (gate input, never gate output) --------
	var candidates []*findings.Finding
	if !runSkipXSS {
		xssFindings, xssErr := tools.RunDalfox(ctx, runner, s, endpoints, ratePerHost, tools.DefaultMaxDalfoxTargets, logger)
		if xssErr != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Warning: dalfox failed: %v\n", xssErr)
		}
		candidates = append(candidates, xssFindings...)
		fmt.Printf("[6/8] xss    : %d candidates\n", len(xssFindings))
	} else {
		fmt.Println("[6/8] xss    : skipped")
	}

	// ---- Stage 7: read-only nuclei posture -------------------------------
	var posture []*findings.Finding
	if !runSkipNuclei {
		nucleiTargets := mergeUnique(append([]string{}, liveURLs...), fuzzURLs...)
		posture, err = tools.RunNucleiPosture(ctx, runner, s, nucleiTargets, rate, logger)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Warning: nuclei failed: %v\n", err)
		}
		fmt.Printf("[7/8] nuclei : %d posture findings\n", len(posture))
	} else {
		fmt.Println("[7/8] nuclei : skipped")
	}

	raw := append(candidates, posture...)
	if err := ws.SaveRawFindings(raw); err != nil {
		return fmt.Errorf("save raw findings: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// ---- Stage 8: the 7-Check gate is the only authority -----------------
	validator := validate.NewValidator(s)
	validated := validator.ValidateAndGroup(ctx, raw)
	if err := ws.SaveValidatedFindings(validated); err != nil {
		return fmt.Errorf("save validated findings: %w", err)
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
	fmt.Printf("[8/8] validate: %d verified, %d needs manual review, %d suppressed\n", verified, manual, suppressed)

	if len(validated) > 0 {
		if err := ws.SaveReportMD(report.GenerateMarkdown(target, validated)); err != nil {
			return fmt.Errorf("save markdown report: %w", err)
		}
	}

	fmt.Printf("\nTier 0/1 pipeline complete. Artifacts in %s\n", ws.Dir)
	fmt.Println("Next steps (Tier 2/3, explicit and human-gated):")
	fmt.Printf("  scoutr triage           --from %s\n", ws.Dir)
	fmt.Printf("  scoutr report --draft   --from %s\n", ws.Dir)
	fmt.Printf("  scoutr submit --require-approval --from %s\n", ws.Dir)
	return nil
}
