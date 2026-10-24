package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
)

// SubdomainResult holds information about a discovered subdomain.
type SubdomainResult struct {
	Host     string   `json:"host"`
	Source   string   `json:"source"`
	IPs      []string `json:"ips,omitempty"`
	Resolved bool     `json:"resolved"`
}

// LogFunc is a logging callback for tool notices.
type LogFunc func(format string, args ...any)

// DefaultLog is a no-op logger.
var DefaultLog LogFunc = func(format string, args ...any) {}

// ExtractRootDomains extracts bare root domains from scope InScope patterns.
func ExtractRootDomains(s *scope.Scope) []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]bool)
	var domains []string
	for _, entry := range s.InScope {
		d := strings.TrimSpace(strings.ToLower(entry))
		d = strings.TrimPrefix(d, "*.")
		if idx := strings.Index(d, ":"); idx != -1 {
			d = d[:idx]
		}
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	return domains
}

// RunSubfinder executes subfinder in passive JSON mode.
func RunSubfinder(ctx context.Context, runner CommandRunner, s *scope.Scope, domains []string, log LogFunc) ([]string, error) {
	if _, err := runner.LookPath("subfinder"); err != nil {
		log("[INFO] subfinder not found on PATH, skipping...")
		return nil, nil
	}

	filteredDomains := FilterTargetsInScope(s, domains)
	if len(filteredDomains) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-json"}
	stdout, _, err := SafeToolExecution(ctx, runner, s, "subfinder", args, filteredDomains, InputModeStdin, "")
	if err != nil {
		return nil, fmt.Errorf("execute subfinder: %w", err)
	}

	var results []string
	seen := make(map[string]bool)
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &item); err == nil && item.Host != "" {
			host := strings.ToLower(strings.TrimSpace(item.Host))
			if FilterDiscoveredItem(s, host) && !seen[host] {
				seen[host] = true
				results = append(results, host)
			}
		}
	}
	return results, scanner.Err()
}

// RunAmass executes amass in passive JSON mode.
func RunAmass(ctx context.Context, runner CommandRunner, s *scope.Scope, domains []string, log LogFunc) ([]string, error) {
	if _, err := runner.LookPath("amass"); err != nil {
		log("[INFO] amass not found on PATH, skipping...")
		return nil, nil
	}

	filteredDomains := FilterTargetsInScope(s, domains)
	if len(filteredDomains) == 0 {
		return nil, nil
	}

	// amass enum -passive -nocolor -json
	args := []string{"enum", "-passive", "-nocolor", "-json"}
	stdout, _, err := SafeToolExecution(ctx, runner, s, "amass", args, filteredDomains, InputModeStdin, "")
	if err != nil {
		return nil, fmt.Errorf("execute amass: %w", err)
	}

	var results []string
	seen := make(map[string]bool)
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &item); err == nil && item.Name != "" {
			host := strings.ToLower(strings.TrimSpace(item.Name))
			if FilterDiscoveredItem(s, host) && !seen[host] {
				seen[host] = true
				results = append(results, host)
			}
		}
	}
	return results, scanner.Err()
}

// RunAssetfinder executes assetfinder with --subs-only.
func RunAssetfinder(ctx context.Context, runner CommandRunner, s *scope.Scope, domains []string, log LogFunc) ([]string, error) {
	if _, err := runner.LookPath("assetfinder"); err != nil {
		log("[INFO] assetfinder not found on PATH, skipping...")
		return nil, nil
	}

	filteredDomains := FilterTargetsInScope(s, domains)
	if len(filteredDomains) == 0 {
		return nil, nil
	}

	args := []string{"--subs-only"}
	stdout, _, err := SafeToolExecution(ctx, runner, s, "assetfinder", args, filteredDomains, InputModeStdin, "")
	if err != nil {
		return nil, fmt.Errorf("execute assetfinder: %w", err)
	}

	var results []string
	seen := make(map[string]bool)
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		host := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if host == "" {
			continue
		}
		if FilterDiscoveredItem(s, host) && !seen[host] {
			seen[host] = true
			results = append(results, host)
		}
	}
	return results, scanner.Err()
}

// RunDNSX resolves hostnames and checks records using dnsx.
func RunDNSX(ctx context.Context, runner CommandRunner, s *scope.Scope, hosts []string, rateLimit int, log LogFunc) ([]SubdomainResult, error) {
	if _, err := runner.LookPath("dnsx"); err != nil {
		log("[INFO] dnsx not found on PATH, skipping...")
		return nil, nil
	}

	filteredHosts := FilterTargetsInScope(s, hosts)
	if len(filteredHosts) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-json"}
	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}

	stdout, _, err := SafeToolExecution(ctx, runner, s, "dnsx", args, filteredHosts, InputModeStdin, "")
	if err != nil {
		return nil, fmt.Errorf("execute dnsx: %w", err)
	}

	var results []SubdomainResult
	seen := make(map[string]bool)
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item struct {
			Host string   `json:"host"`
			A    []string `json:"a"`
			AAAA []string `json:"aaaa"`
		}
		if err := json.Unmarshal([]byte(line), &item); err == nil && item.Host != "" {
			host := strings.ToLower(strings.TrimSpace(item.Host))
			if FilterDiscoveredItem(s, host) && !seen[host] {
				seen[host] = true
				ips := append(item.A, item.AAAA...)
				results = append(results, SubdomainResult{
					Host:     host,
					Source:   "dnsx",
					IPs:      ips,
					Resolved: len(ips) > 0,
				})
			}
		}
	}
	return results, scanner.Err()
}

// HTTPXResult holds the result from the ProjectDiscovery httpx binary.
type HTTPXResult struct {
	URL        string   `json:"url"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
	Live       bool     `json:"live"`
}

// RunPDHTTPX executes ProjectDiscovery httpx probe binary.
func RunPDHTTPX(ctx context.Context, runner CommandRunner, s *scope.Scope, targets []string, rateLimit int, log LogFunc) ([]HTTPXResult, error) {
	if _, err := runner.LookPath("httpx"); err != nil {
		log("[INFO] httpx binary not found on PATH, skipping...")
		return nil, nil
	}

	filteredTargets := FilterTargetsInScope(s, targets)
	if len(filteredTargets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-json", "-no-color"}
	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}

	stdout, _, err := SafeToolExecution(ctx, runner, s, "httpx", args, filteredTargets, InputModeStdin, "")
	if err != nil {
		return nil, fmt.Errorf("execute httpx binary: %w", err)
	}

	var results []HTTPXResult
	seen := make(map[string]bool)
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item struct {
			URL        string   `json:"url"`
			Input      string   `json:"input"`
			Host       string   `json:"host"`
			StatusCode int      `json:"status_code"`
			Title      string   `json:"title"`
			WebServer  string   `json:"webserver"`
			Tech       []string `json:"tech"`
			Failed     bool     `json:"failed"`
		}
		if err := json.Unmarshal([]byte(line), &item); err == nil && !item.Failed {
			targetURL := item.URL
			if targetURL == "" {
				targetURL = item.Input
			}
			if FilterDiscoveredItem(s, targetURL) && !seen[targetURL] {
				seen[targetURL] = true
				results = append(results, HTTPXResult{
					URL:        targetURL,
					Host:       item.Host,
					StatusCode: item.StatusCode,
					Title:      item.Title,
					WebServer:  item.WebServer,
					Tech:       item.Tech,
					Live:       item.StatusCode > 0,
				})
			}
		}
	}
	return results, scanner.Err()
}

// RunURLs collects historical endpoints from waybackurls and gau.
func RunURLs(ctx context.Context, runner CommandRunner, s *scope.Scope, domains []string, log LogFunc) ([]string, error) {
	filteredDomains := FilterTargetsInScope(s, domains)
	if len(filteredDomains) == 0 {
		return nil, nil
	}

	var allURLs []string
	seen := make(map[string]bool)

	// 1. Try gau
	if _, err := runner.LookPath("gau"); err == nil {
		log("[INFO] Running gau for historical archive URLs...")
		args := []string{"--json"}
		stdout, _, err := SafeToolExecution(ctx, runner, s, "gau", args, filteredDomains, InputModeStdin, "")
		if err == nil {
			scanner := SafeLineScanner(strings.NewReader(string(stdout)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				// gau --json outputs JSON or string URLs
				var item struct {
					URL string `json:"url"`
				}
				rawURL := line
				if err := json.Unmarshal([]byte(line), &item); err == nil && item.URL != "" {
					rawURL = item.URL
				}
				if FilterDiscoveredItem(s, rawURL) && !seen[rawURL] {
					seen[rawURL] = true
					allURLs = append(allURLs, rawURL)
				}
			}
		} else {
			log("[WARN] gau execution failed: %v", err)
		}
	} else {
		log("[INFO] gau not found on PATH, skipping...")
	}

	// 2. Try waybackurls
	if _, err := runner.LookPath("waybackurls"); err == nil {
		log("[INFO] Running waybackurls for historical archive URLs...")
		stdout, _, err := SafeToolExecution(ctx, runner, s, "waybackurls", nil, filteredDomains, InputModeStdin, "")
		if err == nil {
			scanner := SafeLineScanner(strings.NewReader(string(stdout)))
			for scanner.Scan() {
				rawURL := strings.TrimSpace(scanner.Text())
				if rawURL == "" {
					continue
				}
				if FilterDiscoveredItem(s, rawURL) && !seen[rawURL] {
					seen[rawURL] = true
					allURLs = append(allURLs, rawURL)
				}
			}
		} else {
			log("[WARN] waybackurls execution failed: %v", err)
		}
	} else {
		log("[INFO] waybackurls not found on PATH, skipping...")
	}

	return allURLs, nil
}

// BuildScopeRegex constructs regex patterns for Katana's crawl scope (-cs) and crawl out-of-scope (-cos).
func BuildScopeRegex(s *scope.Scope) (scopeRegex string, outScopeRegex string) {
	if s == nil {
		return "", ""
	}

	makePattern := func(entries []string) string {
		var parts []string
		for _, entry := range entries {
			entry = strings.TrimSpace(strings.ToLower(entry))
			if entry == "" {
				continue
			}
			if strings.HasPrefix(entry, "*.") {
				base := regexp.QuoteMeta(entry[2:])
				parts = append(parts, fmt.Sprintf(`(?:[a-zA-Z0-9.-]+\.)?%s`, base))
			} else {
				parts = append(parts, regexp.QuoteMeta(entry))
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return fmt.Sprintf(`https?://(?:%s)(?::[0-9]+)?(?:/.*)?`, strings.Join(parts, "|"))
	}

	return makePattern(s.InScope), makePattern(s.OutOfScope)
}

// KatanaResult holds an endpoint discovered during shallow crawling.
type KatanaResult struct {
	Endpoint string `json:"endpoint"`
	Source   string `json:"source"`
}

// RunKatana runs shallow link discovery via katana with scope constraints and no active fuzzing.
func RunKatana(ctx context.Context, runner CommandRunner, s *scope.Scope, targets []string, rateLimit int, depth int, log LogFunc) ([]KatanaResult, error) {
	if _, err := runner.LookPath("katana"); err != nil {
		log("[INFO] katana not found on PATH, skipping...")
		return nil, nil
	}

	filteredTargets := FilterTargetsInScope(s, targets)
	if len(filteredTargets) == 0 {
		return nil, nil
	}

	if depth <= 0 {
		depth = 2
	}

	args := []string{
		"-silent",
		"-jsonl",
		"-d", fmt.Sprintf("%d", depth),
		"-no-color",
	}

	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}

	cs, cos := BuildScopeRegex(s)
	if cs != "" {
		args = append(args, "-cs", cs)
	}
	if cos != "" {
		args = append(args, "-cos", cos)
	}

	stdout, _, err := SafeToolExecution(ctx, runner, s, "katana", args, filteredTargets, InputModeStdin, "")
	if err != nil {
		return nil, fmt.Errorf("execute katana: %w", err)
	}

	var results []KatanaResult
	seen := make(map[string]bool)
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item struct {
			Request struct {
				Endpoint string `json:"endpoint"`
			} `json:"request"`
		}
		if err := json.Unmarshal([]byte(line), &item); err == nil && item.Request.Endpoint != "" {
			ep := item.Request.Endpoint
			if FilterDiscoveredItem(s, ep) && !seen[ep] {
				seen[ep] = true
				results = append(results, KatanaResult{
					Endpoint: ep,
					Source:   "katana",
				})
			}
		}
	}
	return results, scanner.Err()
}

// RunNucleiPosture runs nuclei strictly in read-only informational posture mode with safe template constraints.
func RunNucleiPosture(ctx context.Context, runner CommandRunner, s *scope.Scope, targets []string, rateLimit int, log LogFunc) ([]*findings.Finding, error) {
	if _, err := runner.LookPath("nuclei"); err != nil {
		log("[INFO] nuclei not found on PATH, skipping...")
		return nil, nil
	}

	filteredTargets := FilterTargetsInScope(s, targets)
	if len(filteredTargets) == 0 {
		return nil, nil
	}

	if rateLimit <= 0 {
		rateLimit = 5
	}

	// Strictly constrained read-only observation flags:
	// Allowed tags: ssl,tls,tech,headers,misconfig,exposure
	// Excluded tags: fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf
	args := []string{
		"-silent",
		"-jsonl",
		"-no-interactsh",
		"-c", "5",
		"-rl", fmt.Sprintf("%d", rateLimit),
		"-tags", "ssl,tls,tech,headers,misconfig,exposure",
		"-etags", "fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf",
	}

	// Pass targets via clean temporary file (-l flag) to ensure Windows command-line length limits are respected
	stdout, _, err := SafeToolExecution(ctx, runner, s, "nuclei", args, filteredTargets, InputModeTempFile, "-l")
	if err != nil {
		return nil, fmt.Errorf("execute nuclei: %w", err)
	}

	var results []*findings.Finding
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Reference   any    `json:"reference"`
			} `json:"info"`
			Host      string   `json:"host"`
			MatchedAt string   `json:"matched-at"`
			Extracted []string `json:"extracted-results"`
		}
		if err := json.Unmarshal([]byte(line), &item); err == nil && item.TemplateID != "" {
			target := item.Host
			if target == "" {
				target = item.MatchedAt
			}
			if !FilterDiscoveredItem(s, target) {
				continue
			}

			// Map severity
			sev := findings.SeverityInfo
			switch strings.ToLower(item.Info.Severity) {
			case "low":
				sev = findings.SeverityLow
			case "medium":
				sev = findings.SeverityMedium
			case "high":
				sev = findings.SeverityHigh
			}

			f := findings.NewFinding(
				fmt.Sprintf("NUC-%s", item.TemplateID),
				"nuclei",
				target,
				item.Info.Name,
				sev,
				findings.ConfidenceMedium,
			)
			f.RuleID = item.TemplateID
			f.Impact = item.Info.Description

			if item.MatchedAt != "" {
				u, parseErr := url.Parse(item.MatchedAt)
				if parseErr == nil && u.Path != "" {
					f.Path = u.Path
				}
			}

			if len(item.Extracted) > 0 {
				f.Evidence = strings.Join(item.Extracted, "; ")
			}

			results = append(results, f)
		}
	}

	return results, scanner.Err()
}
