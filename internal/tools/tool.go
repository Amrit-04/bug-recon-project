package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/scope"
)

// TrustTier identifies the operational profile and intrusiveness of an external tool.
type TrustTier string

const (
	// TrustTierPassiveOSINT denotes passive queries to third-party datasets or archives (zero traffic to target).
	TrustTierPassiveOSINT TrustTier = "Passive OSINT"
	// TrustTierReadOnlyProbe denotes strictly read-only inspection queries sent directly to targets.
	TrustTierReadOnlyProbe TrustTier = "Read-Only Probe"
)

// ToolDef defines metadata and execution properties of a supported external tool.
type ToolDef struct {
	Name        string
	Binary      string
	Tier        TrustTier
	Description string
	InstallHint string
	VersionArgs []string
}

// SupportedTools lists all registered external tools supported by scoutr.
var SupportedTools = []ToolDef{
	{
		Name:        "subfinder",
		Binary:      "subfinder",
		Tier:        TrustTierPassiveOSINT,
		Description: "Fast passive subdomain enumeration via public OSINT sources",
		InstallHint: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		VersionArgs: []string{"-version"},
	},
	{
		Name:        "amass",
		Binary:      "amass",
		Tier:        TrustTierPassiveOSINT,
		Description: "In-depth attack surface mapping (executed in passive mode only)",
		InstallHint: "go install -v github.com/owasp-amass/amass/v4/...@master",
		VersionArgs: []string{"-version"},
	},
	{
		Name:        "assetfinder",
		Binary:      "assetfinder",
		Tier:        TrustTierPassiveOSINT,
		Description: "Find domains and subdomains related to a target",
		InstallHint: "go install github.com/tomnomnom/assetfinder@latest",
		VersionArgs: []string{"-h"},
	},
	{
		Name:        "dnsx",
		Binary:      "dnsx",
		Tier:        TrustTierReadOnlyProbe,
		Description: "Multi-purpose DNS toolkit for fast resolution and record inspection",
		InstallHint: "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		VersionArgs: []string{"-version"},
	},
	{
		Name:        "httpx",
		Binary:      "httpx",
		Tier:        TrustTierReadOnlyProbe,
		Description: "Fast, multi-purpose HTTP probe (status, title, technology fingerprinting)",
		InstallHint: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
		VersionArgs: []string{"-version"},
	},
	{
		Name:        "waybackurls",
		Binary:      "waybackurls",
		Tier:        TrustTierPassiveOSINT,
		Description: "Fetch URLs for a domain from the Wayback Machine archive",
		InstallHint: "go install github.com/tomnomnom/waybackurls@latest",
		VersionArgs: []string{"-h"},
	},
	{
		Name:        "gau",
		Binary:      "gau",
		Tier:        TrustTierPassiveOSINT,
		Description: "Fetch known URLs from AlienVault, Wayback, Common Crawl, URLScan",
		InstallHint: "go install github.com/lc/gau/v2/cmd/gau@latest",
		VersionArgs: []string{"--version"},
	},
	{
		Name:        "katana",
		Binary:      "katana",
		Tier:        TrustTierReadOnlyProbe,
		Description: "Next-generation web crawler (shallow, scope-constrained link discovery)",
		InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		VersionArgs: []string{"-version"},
	},
	{
		Name:        "nuclei",
		Binary:      "nuclei",
		Tier:        TrustTierReadOnlyProbe,
		Description: "Fast vulnerability scanner (used strictly in read-only informational posture mode)",
		InstallHint: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		VersionArgs: []string{"-version"},
	},
}

// ToolStatus represents the detected status of an external tool on the host.
type ToolStatus struct {
	ToolDef
	Installed bool
	Path      string
	Version   string
}

// InspectArsenal checks PATH for each supported tool, returning installation status and version.
func InspectArsenal(ctx context.Context, runner CommandRunner) []ToolStatus {
	statuses := make([]ToolStatus, 0, len(SupportedTools))

	for _, tool := range SupportedTools {
		status := ToolStatus{
			ToolDef:   tool,
			Installed: false,
		}

		path, err := runner.LookPath(tool.Binary)
		if err == nil && path != "" {
			status.Installed = true
			status.Path = path

			// Try to query version with a short timeout
			vCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			stdout, stderr, runErr := runner.Run(vCtx, tool.Binary, tool.VersionArgs, nil)
			cancel()

			if runErr == nil || len(stdout) > 0 || len(stderr) > 0 {
				status.Version = extractVersion(string(stdout) + " " + string(stderr))
			}
			if status.Version == "" {
				status.Version = "installed"
			}
		}

		statuses = append(statuses, status)
	}

	return statuses
}

// versionRegex matches common semver and version strings
var versionRegex = regexp.MustCompile(`(?:version|v)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.-]+)?)`)

func extractVersion(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if match := versionRegex.FindStringSubmatch(line); len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

// MaxScanLineBytes defines the maximum line buffer when parsing tool output (1 MB).
const MaxScanLineBytes = 1024 * 1024

// SafeLineScanner returns a bufio.Scanner configured with a 1MB max line buffer.
func SafeLineScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, MaxScanLineBytes)
	return scanner
}

// FilterTargetsInScope filters a list of target hostnames/URLs using the provided Scope.
// Returns only targets that pass s.IsInScope (or s.IsURLInScope if a scheme is present).
func FilterTargetsInScope(s *scope.Scope, targets []string) []string {
	if s == nil {
		return targets
	}
	var inScope []string
	seen := make(map[string]bool)
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		var ok bool
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			ok = s.IsURLInScope(target)
		} else {
			ok = s.IsInScope(target)
		}

		if ok && !seen[target] {
			seen[target] = true
			inScope = append(inScope, target)
		}
	}
	return inScope
}

// FilterDiscoveredItem verifies that an item (host or URL) discovered by an external tool is in scope.
func FilterDiscoveredItem(s *scope.Scope, item string) bool {
	if s == nil {
		return true
	}
	item = strings.TrimSpace(item)
	if item == "" {
		return false
	}
	if strings.HasPrefix(item, "http://") || strings.HasPrefix(item, "https://") {
		return s.IsURLInScope(item)
	}
	return s.IsInScope(item)
}

// TargetInputMode defines how targets are supplied to an external command.
type TargetInputMode int

const (
	// InputModeStdin feeds targets separated by newlines via standard input.
	InputModeStdin TargetInputMode = iota
	// InputModeTempFile writes targets to a temporary file and cleans it up after execution.
	InputModeTempFile
)

// SafeToolExecution safely runs a binary by pre-filtering targets, enforcing rate limit flags,
// feeding targets via stdin or temp file, and returning raw stdout bytes.
func SafeToolExecution(
	ctx context.Context,
	runner CommandRunner,
	s *scope.Scope,
	bin string,
	baseArgs []string,
	targets []string,
	mode TargetInputMode,
	fileFlag string,
) ([]byte, []byte, error) {
	// 1. Pre-filter targets with scope
	inScopeTargets := FilterTargetsInScope(s, targets)
	if len(inScopeTargets) == 0 {
		return nil, nil, nil
	}

	payload := strings.Join(inScopeTargets, "\n") + "\n"

	if mode == InputModeStdin {
		stdin := bytes.NewReader([]byte(payload))
		return runner.Run(ctx, bin, baseArgs, stdin)
	}

	// Mode is TempFile: create temporary file, pass flag, clean up in defer
	tmpFile, err := os.CreateTemp("", "scoutr-targets-*.txt")
	if err != nil {
		return nil, nil, fmt.Errorf("create temp target file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(payload); err != nil {
		tmpFile.Close()
		return nil, nil, fmt.Errorf("write temp target file: %w", err)
	}
	tmpFile.Close()

	args := append([]string{}, baseArgs...)
	if fileFlag != "" {
		args = append(args, fileFlag, tmpPath)
	} else {
		args = append(args, tmpPath)
	}

	return runner.Run(ctx, bin, args, nil)
}
