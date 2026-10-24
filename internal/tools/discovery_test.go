package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
)

func TestRunSubfinder(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	runner.RegisterTool("subfinder", "/bin/subfinder", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		output := `{"host":"api.example.com"}
{"host":"admin.example.com"}
{"host":"other.com"}
`
		return []byte(output), nil, nil
	})

	subs, err := RunSubfinder(context.Background(), runner, s, []string{"example.com"}, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunSubfinder: %v", err)
	}

	if len(subs) != 1 || subs[0] != "api.example.com" {
		t.Errorf("expected only api.example.com, got %v", subs)
	}

	// Test missing tool returns nil without error
	missingRunner := NewMockRunner()
	subsMissing, err := RunSubfinder(context.Background(), missingRunner, s, []string{"example.com"}, DefaultLog)
	if err != nil || subsMissing != nil {
		t.Errorf("expected nil result and nil error for missing subfinder, got %v, %v", subsMissing, err)
	}
}

func TestRunAmass(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	runner.RegisterTool("amass", "/bin/amass", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		output := `{"name":"auth.example.com","domain":"example.com"}
{"name":"forbidden.com","domain":"forbidden.com"}
`
		return []byte(output), nil, nil
	})

	subs, err := RunAmass(context.Background(), runner, s, []string{"example.com"}, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunAmass: %v", err)
	}

	if len(subs) != 1 || subs[0] != "auth.example.com" {
		t.Errorf("expected only auth.example.com, got %v", subs)
	}
}

func TestRunAssetfinder(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	runner.RegisterTool("assetfinder", "/bin/assetfinder", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		output := "dev.example.com\nadmin.example.com\nunrelated.org\n"
		return []byte(output), nil, nil
	})

	subs, err := RunAssetfinder(context.Background(), runner, s, []string{"example.com"}, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunAssetfinder: %v", err)
	}

	if len(subs) != 1 || subs[0] != "dev.example.com" {
		t.Errorf("expected only dev.example.com, got %v", subs)
	}
}

func TestRunDNSX(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedArgs []string
	runner.RegisterTool("dnsx", "/bin/dnsx", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		passedArgs = args
		output := `{"host":"api.example.com","a":["192.0.2.1"]}
{"host":"out.example.com","a":[]}
{"host":"admin.example.com","a":["192.0.2.2"]}
`
		return []byte(output), nil, nil
	})

	results, err := RunDNSX(context.Background(), runner, s, []string{"api.example.com", "out.example.com"}, 15, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunDNSX: %v", err)
	}

	// Verify rate limit flag
	hasRL := false
	for i, arg := range passedArgs {
		if arg == "-rl" && i+1 < len(passedArgs) && passedArgs[i+1] == "15" {
			hasRL = true
		}
	}
	if !hasRL {
		t.Errorf("expected -rl 15 in args, got %v", passedArgs)
	}

	// Verify admin.example.com was dropped by post-filter
	for _, r := range results {
		if r.Host == "admin.example.com" {
			t.Errorf("admin.example.com should have been post-filtered out")
		}
	}
}

func TestRunPDHTTPX(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	runner.RegisterTool("httpx", "/bin/httpx", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		output := `{"url":"https://api.example.com","host":"api.example.com","status_code":200,"title":"API Portal","webserver":"nginx","tech":["Go","Docker"]}
{"url":"https://admin.example.com","host":"admin.example.com","status_code":403,"title":"Forbidden"}
`
		return []byte(output), nil, nil
	})

	results, err := RunPDHTTPX(context.Background(), runner, s, []string{"api.example.com"}, 10, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunPDHTTPX: %v", err)
	}

	if len(results) != 1 || results[0].Host != "api.example.com" {
		t.Errorf("expected only api.example.com, got %v", results)
	}
	if results[0].StatusCode != 200 || results[0].Title != "API Portal" {
		t.Errorf("unexpected probe details: %+v", results[0])
	}
}

func TestRunURLs(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	runner.RegisterTool("gau", "/bin/gau", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		output := `{"url":"https://api.example.com/v1/users"}
{"url":"https://admin.example.com/secret"}
`
		return []byte(output), nil, nil
	})
	runner.RegisterTool("waybackurls", "/bin/waybackurls", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		output := `https://api.example.com/v1/docs
https://forbidden.com/login
`
		return []byte(output), nil, nil
	})

	urls, err := RunURLs(context.Background(), runner, s, []string{"example.com"}, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunURLs: %v", err)
	}

	expected := map[string]bool{
		"https://api.example.com/v1/users": true,
		"https://api.example.com/v1/docs":  true,
	}
	if len(urls) != len(expected) {
		t.Fatalf("expected %d urls, got %d: %v", len(expected), len(urls), urls)
	}
	for _, u := range urls {
		if !expected[u] {
			t.Errorf("unexpected url discovered: %s", u)
		}
	}
}

func TestRunKatana(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedArgs []string
	runner.RegisterTool("katana", "/bin/katana", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		passedArgs = args
		output := `{"request":{"endpoint":"https://api.example.com/docs"}}
{"request":{"endpoint":"https://admin.example.com/secret"}}
`
		return []byte(output), nil, nil
	})

	results, err := RunKatana(context.Background(), runner, s, []string{"https://api.example.com"}, 5, 2, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunKatana: %v", err)
	}

	// Verify scope flags were passed
	var hasCS, hasCOS bool
	for _, arg := range passedArgs {
		if arg == "-cs" {
			hasCS = true
		}
		if arg == "-cos" {
			hasCOS = true
		}
	}
	if !hasCS || !hasCOS {
		t.Errorf("expected -cs and -cos scope flags in katana args: %v", passedArgs)
	}

	if len(results) != 1 || results[0].Endpoint != "https://api.example.com/docs" {
		t.Errorf("expected only https://api.example.com/docs, got %v", results)
	}
}

func TestRunNucleiPosture(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedArgs []string
	runner.RegisterTool("nuclei", "/bin/nuclei", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		passedArgs = args
		output := `{"template-id":"hsts-missing","info":{"name":"Missing Strict Transport Security","severity":"low","description":"HSTS header is absent"},"host":"api.example.com","matched-at":"https://api.example.com"}
{"template-id":"exposed-admin","info":{"name":"Exposed Admin Panel","severity":"medium"},"host":"admin.example.com","matched-at":"https://admin.example.com/admin"}
`
		return []byte(output), nil, nil
	})

	findingsList, err := RunNucleiPosture(context.Background(), runner, s, []string{"api.example.com"}, 5, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error in RunNucleiPosture: %v", err)
	}

	// Verify required safe constraints are in args
	argStr := strings.Join(passedArgs, " ")
	if !strings.Contains(argStr, "-no-interactsh") {
		t.Errorf("nuclei must enforce -no-interactsh")
	}
	if !strings.Contains(argStr, "-tags ssl,tls,tech,headers,misconfig,exposure") {
		t.Errorf("nuclei must restrict tags to read-only posture observation: %v", passedArgs)
	}
	if !strings.Contains(argStr, "-etags fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf") {
		t.Errorf("nuclei must explicitly exclude intrusive/exploit tags: %v", passedArgs)
	}

	if len(findingsList) != 1 {
		t.Fatalf("expected 1 finding (admin.example.com dropped), got %d", len(findingsList))
	}
	f := findingsList[0]
	if f.Target != "api.example.com" {
		t.Errorf("expected target api.example.com, got %s", f.Target)
	}
	if f.Severity != findings.SeverityLow {
		t.Errorf("expected severity low, got %s", f.Severity)
	}
	if f.RuleID != "hsts-missing" {
		t.Errorf("expected RuleID hsts-missing, got %s", f.RuleID)
	}
}
