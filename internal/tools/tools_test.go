package tools

import (
	"context"
	"fmt"
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
