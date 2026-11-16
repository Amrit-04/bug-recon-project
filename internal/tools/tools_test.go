package tools

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/scope"
)

func createTestScope(t *testing.T) *scope.Scope {
	content := `
in_scope:
  - "*.example.com"
  - "example.com"
out_of_scope:
  - "admin.example.com"
  - "forbidden.com"
`
	tmp, err := os.CreateTemp("", "test-scope-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp scope: %v", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("failed to write temp scope: %v", err)
	}
	tmp.Close()

	s, err := scope.LoadFromFile(tmp.Name())
	if err != nil {
		t.Fatalf("failed to load scope: %v", err)
	}
	return s
}

func TestMockRunner(t *testing.T) {
	runner := NewMockRunner()

	// Initially not installed
	_, err := runner.LookPath("subfinder")
	if err == nil {
		t.Fatalf("expected error for uninstalled tool, got nil")
	}

	// Register subfinder
	runner.RegisterTool("subfinder", "/usr/bin/subfinder", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte("v2.6.0\n"), nil, nil
	})

	path, err := runner.LookPath("subfinder")
	if err != nil {
		t.Fatalf("unexpected error looking up path: %v", err)
	}
	if path != "/usr/bin/subfinder" {
		t.Errorf("expected /usr/bin/subfinder, got %s", path)
	}

	stdout, stderr, err := runner.Run(context.Background(), "subfinder", []string{"-version"}, nil)
	if err != nil {
		t.Fatalf("unexpected error running mock tool: %v", err)
	}
	if len(stderr) > 0 {
		t.Errorf("expected empty stderr, got %s", string(stderr))
	}
	if !strings.Contains(string(stdout), "v2.6.0") {
		t.Errorf("expected stdout to contain v2.6.0, got %s", string(stdout))
	}

	calls := runner.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Bin != "subfinder" {
		t.Errorf("expected call bin subfinder, got %s", calls[0].Bin)
	}
}

func TestInspectArsenal(t *testing.T) {
	runner := NewMockRunner()
	runner.RegisterTool("subfinder", "/bin/subfinder", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte("subfinder version 2.6.6\n"), nil, nil
	})
	runner.RegisterTool("dnsx", "/bin/dnsx", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		return []byte("dnsx v1.2.1\n"), nil, nil
	})

	ctx := context.Background()
	statuses := InspectArsenal(ctx, runner)

	if len(statuses) != len(SupportedTools) {
		t.Fatalf("expected %d tools, got %d", len(SupportedTools), len(statuses))
	}

	var foundSubfinder, foundDnsx, foundAmass bool
	for _, s := range statuses {
		if s.Name == "subfinder" {
			foundSubfinder = true
			if !s.Installed {
				t.Errorf("expected subfinder to be installed")
			}
			if s.Version != "2.6.6" {
				t.Errorf("expected subfinder version 2.6.6, got %s", s.Version)
			}
			if s.Tier != TrustTierPassiveOSINT {
				t.Errorf("expected Passive OSINT tier, got %s", s.Tier)
			}
		}
		if s.Name == "dnsx" {
			foundDnsx = true
			if !s.Installed {
				t.Errorf("expected dnsx to be installed")
			}
			if s.Version != "1.2.1" {
				t.Errorf("expected dnsx version 1.2.1, got %s", s.Version)
			}
			if s.Tier != TrustTierReadOnlyProbe {
				t.Errorf("expected Read-Only Probe tier, got %s", s.Tier)
			}
		}
		if s.Name == "amass" {
			foundAmass = true
			if s.Installed {
				t.Errorf("expected amass to NOT be installed")
			}
		}
	}

	if !foundSubfinder || !foundDnsx || !foundAmass {
		t.Errorf("did not find expected tools in arsenal results")
	}
}

func TestScopePreAndPostFiltering(t *testing.T) {
	s := createTestScope(t)

	// Pre-filter
	targets := []string{
		"api.example.com",
		"admin.example.com", // out of scope
		"evil.com",          // out of scope
		"https://sub.example.com/api",
		"http://forbidden.com/login", // out of scope
	}

	filtered := FilterTargetsInScope(s, targets)
	expected := []string{"api.example.com", "https://sub.example.com/api"}
	if len(filtered) != len(expected) {
		t.Fatalf("expected %d in-scope targets, got %d: %v", len(expected), len(filtered), filtered)
	}
	for i, v := range expected {
		if filtered[i] != v {
			t.Errorf("expected %s at index %d, got %s", v, i, filtered[i])
		}
	}

	// Post-filter
	if !FilterDiscoveredItem(s, "app.example.com") {
		t.Errorf("app.example.com should be in scope")
	}
	if FilterDiscoveredItem(s, "admin.example.com") {
		t.Errorf("admin.example.com should be out of scope")
	}
	if FilterDiscoveredItem(s, "https://forbidden.com/path") {
		t.Errorf("forbidden.com URL should be out of scope")
	}
}

func TestSafeToolExecutionStdin(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var receivedStdin string
	runner.RegisterTool("subfinder", "/bin/subfinder", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		receivedStdin = string(stdin)
		return []byte("{\"host\":\"api.example.com\"}\n{\"host\":\"out-of-scope.com\"}\n"), nil, nil
	})

	targets := []string{"api.example.com", "forbidden.com"}
	stdout, _, err := SafeToolExecution(
		context.Background(),
		runner,
		s,
		"subfinder",
		[]string{"-silent", "-json"},
		targets,
		InputModeStdin,
		"",
	)
	if err != nil {
		t.Fatalf("unexpected error running tool: %v", err)
	}

	// Check that forbidden.com was stripped before stdin
	if strings.Contains(receivedStdin, "forbidden.com") {
		t.Errorf("forbidden.com was not stripped from stdin: %s", receivedStdin)
	}
	if !strings.Contains(receivedStdin, "api.example.com") {
		t.Errorf("api.example.com was not sent in stdin: %s", receivedStdin)
	}

	// Parse output and post-filter
	scanner := SafeLineScanner(strings.NewReader(string(stdout)))
	var discovered []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "api.example.com") && FilterDiscoveredItem(s, "api.example.com") {
			discovered = append(discovered, "api.example.com")
		}
		if strings.Contains(line, "out-of-scope.com") && FilterDiscoveredItem(s, "out-of-scope.com") {
			discovered = append(discovered, "out-of-scope.com")
		}
	}
	if len(discovered) != 1 || discovered[0] != "api.example.com" {
		t.Errorf("expected only api.example.com in post-filtered discovery, got %v", discovered)
	}
}

func TestSafeToolExecutionTempFile(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedFilePath string
	runner.RegisterTool("nuclei", "/bin/nuclei", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		for i, arg := range args {
			if arg == "-l" && i+1 < len(args) {
				passedFilePath = args[i+1]
			}
		}
		// Verify file exists during execution
		if _, err := os.Stat(passedFilePath); err != nil {
			return nil, nil, fmt.Errorf("temp file not accessible: %w", err)
		}
		return []byte("nuclei result\n"), nil, nil
	})

	targets := []string{"app.example.com"}
	_, _, err := SafeToolExecution(
		context.Background(),
		runner,
		s,
		"nuclei",
		[]string{"-c", "5"},
		targets,
		InputModeTempFile,
		"-l",
	)
	if err != nil {
		t.Fatalf("unexpected error in temp file tool execution: %v", err)
	}

	if passedFilePath == "" {
		t.Fatalf("expected -l flag with temp file path")
	}

	// Verify temp file was cleaned up (defer os.Remove)
	if _, err := os.Stat(passedFilePath); !os.IsNotExist(err) {
		t.Errorf("expected temp file %s to be deleted after execution, but it still exists", passedFilePath)
	}
}

type toolsMockDNS struct {
	records map[string][]string
}

func (m *toolsMockDNS) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if ips, ok := m.records[host]; ok {
		var out []net.IP
		for _, ipStr := range ips {
			out = append(out, net.ParseIP(ipStr))
		}
		return out, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

func TestExternalToolScopeExclusionFlags(t *testing.T) {
	s := createTestScope(t) // has out_of_scope: admin.example.com, forbidden.com
	runner := NewMockRunner()

	// 1. Test Naabu receives -eh flag
	var naabuArgs []string
	runner.RegisterTool("naabu", "/bin/naabu", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		naabuArgs = args
		return []byte(`{"host":"api.example.com","port":443,"protocol":"tcp"}` + "\n"), nil, nil
	})
	_, err := RunNaabu(context.Background(), runner, s, []string{"api.example.com"}, 100, 10, DefaultLog)
	if err != nil {
		t.Fatalf("RunNaabu error: %v", err)
	}
	hasNaabuEH := false
	for i, a := range naabuArgs {
		if a == "-eh" && i+1 < len(naabuArgs) && strings.Contains(naabuArgs[i+1], "admin.example.com") {
			hasNaabuEH = true
			break
		}
	}
	if !hasNaabuEH {
		t.Errorf("expected naabu to receive -eh flag with out_of_scope targets, got %v", naabuArgs)
	}

	// 2. Test Katana receives -dr, -no-redirects, -duc, -aff=false
	var katanaArgs []string
	runner.RegisterTool("katana", "/bin/katana", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		katanaArgs = args
		return []byte(`{"request":{"endpoint":"https://api.example.com/v1"}}` + "\n"), nil, nil
	})
	_, err = RunKatana(context.Background(), runner, s, []string{"https://api.example.com"}, 5, 2, DefaultLog)
	if err != nil {
		t.Fatalf("RunKatana error: %v", err)
	}
	for _, expectedFlag := range []string{"-dr", "-no-redirects", "-duc", "-aff=false"} {
		found := false
		for _, a := range katanaArgs {
			if a == expectedFlag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected katana to receive flag %s, got %v", expectedFlag, katanaArgs)
		}
	}

	// 3. Test Nuclei receives -dr, -duc, -eh
	var nucleiArgs []string
	runner.RegisterTool("nuclei", "/bin/nuclei", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		nucleiArgs = args
		return []byte(`{"template-id":"ssl-dns","info":{"name":"SSL Info","severity":"info"},"host":"api.example.com"}` + "\n"), nil, nil
	})
	_, err = RunNucleiPosture(context.Background(), runner, s, []string{"api.example.com"}, 5, DefaultLog)
	if err != nil {
		t.Fatalf("RunNucleiPosture error: %v", err)
	}
	for _, expectedFlag := range []string{"-dr", "-duc", "-eh"} {
		found := false
		for _, a := range nucleiArgs {
			if a == expectedFlag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected nuclei to receive flag %s, got %v", expectedFlag, nucleiArgs)
		}
	}
}

func TestDNSResolutionScopeEnforcement(t *testing.T) {
	s := scope.New(
		[]string{"*.example.com", "example.com"},
		[]string{"admin.example.com", "10.0.0.0/8"},
	)
	mockDNS := &toolsMockDNS{
		records: map[string][]string{
			"safe.example.com": {"93.184.216.34"},
			"sub.example.com":  {"10.0.0.50"}, // Resolves to 10.0.0.0/8 (out of scope!)
			"fuzz.example.com": {"10.0.0.99"}, // Resolves to 10.0.0.0/8 (out of scope!)
		},
	}
	s.SetResolver(mockDNS)

	runner := NewMockRunner()
	nmapCalled := 0
	runner.RegisterTool("nmap", "/bin/nmap", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		nmapCalled++
		return []byte(`<nmaprun></nmaprun>`), nil, nil
	})

	// Run nmap against both safe host and out-of-scope resolved host
	targets := []NmapTarget{
		{Host: "safe.example.com", Ports: []int{443}},
		{Host: "sub.example.com", Ports: []int{443}}, // must be blocked by DNS scope check!
	}
	_, err := RunNmapServiceScan(context.Background(), runner, s, targets, 5, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunNmapServiceScan: %v", err)
	}

	if nmapCalled != 1 {
		t.Errorf("expected nmap to be called exactly once for safe host, got %d calls", nmapCalled)
	}

	// Test FFUF DNS enforcement
	ffufCalled := 0
	runner.RegisterTool("ffuf", "/bin/ffuf", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		ffufCalled++
		outPath := argValue(args, "-o")
		_ = os.WriteFile(outPath, []byte(`{"results":[]}`), 0644)
		return nil, nil, nil
	})

	_, err = RunFFUF(context.Background(), runner, s, []string{"https://fuzz.example.com"}, 5, 10, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunFFUF: %v", err)
	}
	if ffufCalled != 0 {
		t.Errorf("expected ffuf NOT to be called against host resolving to out-of-scope IP, got %d calls", ffufCalled)
	}
}
