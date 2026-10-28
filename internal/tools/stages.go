package tools

// Tier 1 (active scanning) stages: naabu, nmap, ffuf and dalfox.
//
// Every stage in this file obeys the same contract as the passive stages in
// discovery.go:
//
//  1. Targets are scope-filtered BEFORE any binary is executed.
//  2. Discovered hosts/URLs are scope-filtered AFTER parsing.
//  3. Missing binaries degrade gracefully (log + nil result, no error).
//  4. Output is parsed from structured (JSON/XML) records only, never scraped.
//  5. Hard-coded conservative defaults, rate limits and target caps apply.

import (
	"context"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/scope"
)

// Conservative Tier 1 defaults. These are constants on purpose: the pipeline
// sequence and its budgets are code, never model output.
const (
	// DefaultNaabuTopPorts is the only port budget used unless the operator
	// explicitly opts into the 1,000-port profile.
	DefaultNaabuTopPorts = 100
	// AlternateNaabuTopPorts is the opt-in wider profile (still far from 65,535).
	AlternateNaabuTopPorts = 1000

	// DefaultMaxFFUFTargets caps how many hosts receive content discovery.
	DefaultMaxFFUFTargets = 25
	// DefaultMaxDalfoxTargets caps how many parameterised endpoints get XSS probes.
	DefaultMaxDalfoxTargets = 50

	// ffufMatchCodes keeps only interesting-but-harmless response classes.
	ffufMatchCodes = "200,204,301,302,307,308,401,403,405"
)

//go:embed wordlist_paths.txt
var embeddedPathWordlist string

// DefaultPathWordlist returns the curated, deliberately small ffuf wordlist
// embedded in the binary. It is a short list of common paths, not a
// brute-force-everything dictionary.
func DefaultPathWordlist() string {
	return embeddedPathWordlist
}

// WritePathWordlist materialises the embedded wordlist into a temporary file so
// it can be passed to ffuf via -w. The caller owns cleanup.
func WritePathWordlist() (string, error) {
	f, err := os.CreateTemp("", "scoutr-ffuf-paths-*.txt")
	if err != nil {
		return "", fmt.Errorf("create ffuf wordlist: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(embeddedPathWordlist); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("write ffuf wordlist: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("close ffuf wordlist: %w", err)
	}
	return path, nil
}

// PortResult is one open port, optionally enriched by nmap service detection.
type PortResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source"`
}

// NormalizeTopPorts clamps the requested port budget to one of the two
// supported profiles. Anything else (including 65535) falls back to the
// conservative default.
func NormalizeTopPorts(n int) int {
	switch n {
	case DefaultNaabuTopPorts, AlternateNaabuTopPorts:
		return n
	default:
		return DefaultNaabuTopPorts
	}
}

// RunNaabu discovers open ports using only the top-100 (default) or top-1000
// profile, with a connect scan and a mandatory rate limit. Hosts are supplied
// through stdin so OS argument length limits never matter.
func RunNaabu(ctx context.Context, runner CommandRunner, s *scope.Scope, hosts []string, topPorts, rateLimit int, log LogFunc) ([]PortResult, error) {
	if _, err := runner.LookPath("naabu"); err != nil {
		log("[INFO] naabu not found on PATH, skipping port discovery...")
		return nil, nil
	}

	filteredHosts := FilterTargetsInScope(s, hosts)
	if len(filteredHosts) == 0 {
		return nil, nil
	}

	ports := NormalizeTopPorts(topPorts)
	if topPorts != ports {
		log("[WARN] unsupported naabu port budget %d, using top %d ports", topPorts, ports)
	}
	if rateLimit <= 0 {
		rateLimit = 5
	}

	args := []string{
		"-silent",
		"-json",
		"-top-ports", strconv.Itoa(ports),
		"-scan-type", "c", // TCP connect: no raw sockets, no elevated privileges
		"-exclude-cdn",
		"-rl", strconv.Itoa(rateLimit),
	}

	stdout, _, err := SafeToolExecution(ctx, runner, s, "naabu", args, filteredHosts, InputModeStdin, "")
	if err != nil {
		return nil, fmt.Errorf("execute naabu: %w", err)
	}

	var results []PortResult
	seen := make(map[string]bool)
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item struct {
			Host     string `json:"host"`
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}
		if err := json.Unmarshal([]byte(line), &item); err != nil || item.Host == "" || item.Port <= 0 {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(item.Host))
		if !FilterDiscoveredItem(s, host) {
			continue
		}
		key := fmt.Sprintf("%s:%d", host, item.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, PortResult{
			Host:     host,
			IP:       item.IP,
			Port:     item.Port,
			Protocol: item.Protocol,
			Source:   "naabu",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan naabu output: %w", err)
	}

	SortPorts(results)
	return results, nil
}

// SortPorts orders port results deterministically (host, then port).
func SortPorts(list []PortResult) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Host == list[j].Host {
			return list[i].Port < list[j].Port
		}
		return list[i].Host < list[j].Host
	})
}

// NmapTarget is a host plus the exact ports naabu discovered for it.
type NmapTarget struct {
	Host  string `json:"host"`
	Ports []int  `json:"ports"`
}

// NmapTargets groups naabu results per host, preserving order.
func NmapTargets(ports []PortResult) []NmapTarget {
	byHost := make(map[string][]int)
	var order []string
	for _, p := range ports {
		if _, ok := byHost[p.Host]; !ok {
			order = append(order, p.Host)
		}
		byHost[p.Host] = appendUniqueInt(byHost[p.Host], p.Port)
	}
	targets := make([]NmapTarget, 0, len(order))
	for _, host := range order {
		sort.Ints(byHost[host])
		targets = append(targets, NmapTarget{Host: host, Ports: byHost[host]})
	}
	return targets
}

func appendUniqueInt(slice []int, v int) []int {
	for _, existing := range slice {
		if existing == v {
			return slice
		}
	}
	return append(slice, v)
}

// nmapXML models the subset of nmap -oX output scoutr consumes.
type nmapXML struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Addresses []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// RunNmapServiceScan runs `nmap -sV` on exactly the ports naabu discovered.
// It never performs a broad port scan: the -p list is always explicit and
// empty target sets are skipped.
func RunNmapServiceScan(ctx context.Context, runner CommandRunner, s *scope.Scope, targets []NmapTarget, rateLimit int, log LogFunc) ([]PortResult, error) {
	if _, err := runner.LookPath("nmap"); err != nil {
		log("[INFO] nmap not found on PATH, skipping service detection...")
		return nil, nil
	}

	if rateLimit <= 0 {
		rateLimit = 5
	}
	// nmap --max-rate is packets per second; derive a conservative cap from the
	// configured request rate instead of letting nmap decide.
	maxRate := rateLimit * 10
	if maxRate < 10 {
		maxRate = 10
	}
	if maxRate > 500 {
		maxRate = 500
	}

	var results []PortResult
	for _, target := range targets {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		host := strings.ToLower(strings.TrimSpace(target.Host))
		if host == "" || len(target.Ports) == 0 {
			continue
		}
		if !FilterDiscoveredItem(s, host) {
			continue
		}

		portList := make([]string, 0, len(target.Ports))
		for _, p := range target.Ports {
			if p > 0 && p <= 65535 {
				portList = append(portList, strconv.Itoa(p))
			}
		}
		if len(portList) == 0 {
			continue
		}

		args := []string{
			"-sV",             // service/version detection only
			"--version-light", // low intensity probes
			"-Pn",             // treat hosts as up, no discovery sweep
			"-T3",
			"--max-rate", strconv.Itoa(maxRate),
			"--max-retries", "1",
			"--host-timeout", "60s",
			"-p", strings.Join(portList, ","),
			"-oX", "-",
			host,
		}

		log("[INFO] nmap -sV on %s (%d discovered ports)", host, len(portList))
		stdout, stderr, err := runner.Run(ctx, "nmap", args, nil)
		if err != nil {
			log("[WARN] nmap failed on %s: %v (%s)", host, err, strings.TrimSpace(string(stderr)))
			continue
		}

		var doc nmapXML
		if err := xml.Unmarshal(stdout, &doc); err != nil {
			log("[WARN] unable to parse nmap XML for %s: %v", host, err)
			continue
		}

		for _, h := range doc.Hosts {
			ip := ""
			for _, addr := range h.Addresses {
				if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
					ip = addr.Addr
					break
				}
			}
			for _, p := range h.Ports {
				if p.State.State != "open" && p.State.State != "open|filtered" {
					continue
				}
				results = append(results, PortResult{
					Host:     host,
					IP:       ip,
					Port:     p.PortID,
					Protocol: p.Protocol,
					Service:  p.Service.Name,
					Product:  p.Service.Product,
					Version:  p.Service.Version,
					Source:   "nmap",
				})
			}
		}
	}

	SortPorts(results)
	return results, nil
}

// BuildHTTPXTargets feeds naabu's open ports into httpx. Hosts without an
// explicit port keep a scheme-less entry so httpx can probe 80/443, and every
// discovered port becomes a host:port entry.
func BuildHTTPXTargets(hosts []string, ports []PortResult) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	for _, h := range hosts {
		add(h)
	}
	for _, p := range ports {
		add(fmt.Sprintf("%s:%d", p.Host, p.Port))
	}
	return out
}

// FFUFResult is one discovered path returned by ffuf.
type FFUFResult struct {
	URL              string            `json:"url"`
	Input            map[string]string `json:"input,omitempty"`
	Status           int               `json:"status"`
	Length           int               `json:"length"`
	Words            int               `json:"words"`
	Lines            int               `json:"lines"`
	ContentType      string            `json:"content_type,omitempty"`
	RedirectLocation string            `json:"redirect_location,omitempty"`
	Source           string            `json:"source"`
}

// fuzzableURL converts a host/URL into an ffuf FUZZ template. Targets that
// already carry a query string are skipped: path discovery must not mutate
// application state through query parameters.
func fuzzableURL(target string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" || strings.Contains(target, "?") {
		return "", false
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
	if _, err := url.Parse(target); err != nil {
		return "", false
	}
	return strings.TrimSuffix(target, "/") + "/FUZZ", true
}

// RunFFUF performs curated content/path discovery on in-scope hosts.
//
// Each host receives a single ffuf process with the embedded short wordlist,
// the per-host rate limit and a low thread count. ffuf writes JSON to a temp
// file (-of json -o <file>), which is the only structured output we parse.
func RunFFUF(ctx context.Context, runner CommandRunner, s *scope.Scope, targets []string, rateLimit, maxTargets int, log LogFunc) ([]FFUFResult, error) {
	if _, err := runner.LookPath("ffuf"); err != nil {
		log("[INFO] ffuf not found on PATH, skipping content discovery...")
		return nil, nil
	}

	filteredTargets := FilterTargetsInScope(s, targets)
	if len(filteredTargets) == 0 {
		return nil, nil
	}

	if rateLimit <= 0 {
		rateLimit = 3
	}
	if maxTargets <= 0 {
		maxTargets = DefaultMaxFFUFTargets
	}
	if len(filteredTargets) > maxTargets {
		log("[INFO] ffuf target cap reached: scanning %d of %d hosts", maxTargets, len(filteredTargets))
		filteredTargets = filteredTargets[:maxTargets]
	}

	wordlist, err := WritePathWordlist()
	if err != nil {
		return nil, err
	}
	defer os.Remove(wordlist)

	var results []FFUFResult
	seen := make(map[string]bool)

	for _, target := range filteredTargets {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		template, ok := fuzzableURL(target)
		if !ok {
			continue
		}

		outFile, err := os.CreateTemp("", "scoutr-ffuf-out-*.json")
		if err != nil {
			return results, fmt.Errorf("create ffuf output file: %w", err)
		}
		outPath := outFile.Name()
		outFile.Close()

		args := []string{
			"-u", template,
			"-w", wordlist,
			"-of", "json",
			"-o", outPath,
			"-mc", ffufMatchCodes,
			"-t", "5",
			"-rate", strconv.Itoa(rateLimit),
			"-timeout", "10",
			"-s",
			"-noninteractive",
		}

		log("[INFO] ffuf content discovery: %s (rate %d/s)", template, rateLimit)
		_, stderr, runErr := runner.Run(ctx, "ffuf", args, nil)
		if runErr != nil {
			log("[WARN] ffuf failed on %s: %v (%s)", template, runErr, strings.TrimSpace(string(stderr)))
		}

		data, readErr := os.ReadFile(outPath)
		os.Remove(outPath)
		if readErr != nil {
			continue
		}

		var doc struct {
			Results []struct {
				URL      string            `json:"url"`
				Input    map[string]string `json:"input"`
				Status   int               `json:"status"`
				Length   int               `json:"length"`
				Words    int               `json:"words"`
				Lines    int               `json:"lines"`
				Content  string            `json:"content-type"`
				Redirect string            `json:"redirectlocation"`
			} `json:"results"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			log("[WARN] unable to parse ffuf JSON for %s: %v", template, err)
			continue
		}

		for _, r := range doc.Results {
			if r.URL == "" || !FilterDiscoveredItem(s, r.URL) {
				continue
			}
			if seen[r.URL] {
				continue
			}
			seen[r.URL] = true
			results = append(results, FFUFResult{
				URL:              r.URL,
				Input:            r.Input,
				Status:           r.Status,
				Length:           r.Length,
				Words:            r.Words,
				Lines:            r.Lines,
				ContentType:      r.Content,
				RedirectLocation: r.Redirect,
				Source:           "ffuf",
			})
		}
	}

	sort.SliceStable(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	return results, nil
}

// DalfoxResult is a raw XSS probe result. It is a gate candidate, never a
// verified vulnerability on its own.
type DalfoxResult struct {
	URL        string `json:"url"`
	Param      string `json:"param,omitempty"`
	Payload    string `json:"payload,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	PoC        string `json:"poc,omitempty"`
	InjectType string `json:"inject_type,omitempty"`
	Method     string `json:"method,omitempty"`
	Severity   string `json:"severity,omitempty"`
	CWE        string `json:"cwe,omitempty"`
}

// IsParameterisedURL reports whether a URL has a query parameter worth probing.
func IsParameterisedURL(rawURL string) bool {
	if !strings.Contains(rawURL, "?") || !strings.Contains(rawURL, "=") {
		return false
	}
	_, err := url.Parse(rawURL)
	return err == nil
}

// RunDalfox probes parameterised in-scope endpoints for XSS with headless DOM
// verification. The per-host rate limit is enforced through --delay with a
// single worker; findings are returned as candidates for the 7-Check gate.
func RunDalfox(ctx context.Context, runner CommandRunner, s *scope.Scope, urls []string, ratePerHost, maxTargets int, log LogFunc) ([]*findings.Finding, error) {
	if _, err := runner.LookPath("dalfox"); err != nil {
		log("[INFO] dalfox not found on PATH, skipping XSS probing...")
		return nil, nil
	}

	var candidates []string
	seen := make(map[string]bool)
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] || !IsParameterisedURL(u) {
			continue
		}
		if !FilterDiscoveredItem(s, u) {
			continue
		}
		seen[u] = true
		candidates = append(candidates, u)
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	if ratePerHost <= 0 {
		ratePerHost = 3
	}
	delayMs := 1000 / ratePerHost
	if delayMs < 100 {
		delayMs = 100
	}
	if maxTargets <= 0 {
		maxTargets = DefaultMaxDalfoxTargets
	}
	if len(candidates) > maxTargets {
		log("[INFO] dalfox target cap reached: probing %d of %d endpoints", maxTargets, len(candidates))
		candidates = candidates[:maxTargets]
	}

	var results []*findings.Finding
	for _, target := range candidates {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		outFile, err := os.CreateTemp("", "scoutr-dalfox-*.json")
		if err != nil {
			return results, fmt.Errorf("create dalfox output file: %w", err)
		}
		outPath := outFile.Name()
		outFile.Close()

		args := []string{
			"url", target,
			"--deep-domxss",
			"--format", "json",
			"--output", outPath,
			"--silence",
			"--no-spinner",
			"--worker", "1",
			"--delay", strconv.Itoa(delayMs),
			"--timeout", "10",
		}

		log("[INFO] dalfox XSS probe: %s (worker 1, delay %dms)", target, delayMs)
		_, stderr, runErr := runner.Run(ctx, "dalfox", args, nil)
		if runErr != nil {
			log("[WARN] dalfox failed on %s: %v (%s)", target, runErr, strings.TrimSpace(string(stderr)))
		}

		data, readErr := os.ReadFile(outPath)
		os.Remove(outPath)
		if readErr != nil {
			continue
		}

		for _, raw := range decodeJSONRecords(data) {
			var item struct {
				URL        string `json:"url"`
				Param      string `json:"param"`
				Payload    string `json:"payload"`
				Evidence   string `json:"evidence"`
				PoC        string `json:"poc"`
				InjectType string `json:"inject_type"`
				Method     string `json:"method"`
				Severity   string `json:"severity"`
				CWE        string `json:"cwe"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				continue
			}
			res := DalfoxResult{
				URL:        firstNonEmpty(item.URL, item.PoC, target),
				Param:      item.Param,
				Payload:    item.Payload,
				Evidence:   item.Evidence,
				PoC:        item.PoC,
				InjectType: item.InjectType,
				Method:     item.Method,
				Severity:   item.Severity,
				CWE:        item.CWE,
			}
			if !FilterDiscoveredItem(s, res.URL) {
				continue
			}
			results = append(results, dalfoxToFinding(res, target))
		}
	}

	return results, nil
}

// dalfoxToFinding converts a dalfox probe record into a low-confidence finding.
// The 7-Check gate decides whether it survives; the scanner does not.
func dalfoxToFinding(res DalfoxResult, probedURL string) *findings.Finding {
	sev := findings.SeverityMedium
	switch strings.ToLower(res.Severity) {
	case "critical":
		sev = findings.SeverityCritical
	case "high":
		sev = findings.SeverityHigh
	case "low":
		sev = findings.SeverityLow
	}

	title := "Candidate XSS (dalfox)"
	if res.Param != "" {
		title = fmt.Sprintf("Candidate XSS in parameter %q (dalfox)", res.Param)
	}

	f := findings.NewFinding(
		fmt.Sprintf("DALFOX-%08x", fnv32(res.URL+"|"+res.Param+"|"+res.Payload)),
		"dalfox",
		res.URL,
		title,
		sev,
		findings.ConfidenceLow,
	)
	f.RuleID = firstNonEmpty(res.InjectType, "xss")
	f.Impact = "Dalfox reported a reflected/DOM XSS candidate. This is an unverified candidate: the 7-Check gate and a human reviewer must confirm exploitability."
	f.Evidence = firstNonEmpty(res.Evidence, res.PoC, res.Payload)
	f.Request = fmt.Sprintf("%s %s", firstNonEmpty(res.Method, "GET"), firstNonEmpty(res.PoC, probedURL))
	if res.CWE != "" {
		f.References = []string{"https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(strings.ToUpper(res.CWE), "CWE-") + ".html"}
	}
	if u, err := url.Parse(res.URL); err == nil {
		f.Path = u.Path
	}
	return f
}

// decodeJSONRecords accepts either a JSON array or line-delimited JSON objects,
// which covers dalfox's JSON output across versions.
func decodeJSONRecords(data []byte) []json.RawMessage {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var list []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &list); err == nil {
			return list
		}
		return nil
	}
	var records []json.RawMessage
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if json.Valid([]byte(line)) {
			records = append(records, json.RawMessage(line))
		}
	}
	return records
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func fnv32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
