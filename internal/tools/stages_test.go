package tools

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/scoutr/scoutr/internal/findings"
)

// argValue returns the value following flag in args, if present.
func argValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func TestNormalizeTopPorts(t *testing.T) {
	cases := map[int]int{
		0:     DefaultNaabuTopPorts,
		100:   DefaultNaabuTopPorts,
		1000:  AlternateNaabuTopPorts,
		65535: DefaultNaabuTopPorts,
		10000: DefaultNaabuTopPorts,
		-1:    DefaultNaabuTopPorts,
	}
	for in, want := range cases {
		if got := NormalizeTopPorts(in); got != want {
			t.Errorf("NormalizeTopPorts(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestRunNaabu(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedArgs []string
	runner.RegisterTool("naabu", "/bin/naabu", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		passedArgs = args
		output := `{"host":"api.example.com","ip":"192.0.2.10","port":443,"protocol":"tcp"}
{"host":"api.example.com","ip":"192.0.2.10","port":8443,"protocol":"tcp"}
{"host":"api.example.com","ip":"192.0.2.10","port":443,"protocol":"tcp"}
{"host":"admin.example.com","ip":"192.0.2.11","port":22,"protocol":"tcp"}
`
		return []byte(output), nil, nil
	})

	ports, err := RunNaabu(context.Background(), runner, s, []string{"api.example.com", "admin.example.com"}, 0, 10, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ports) != 2 {
		t.Fatalf("expected 2 unique in-scope ports, got %d: %+v", len(ports), ports)
	}
	if ports[0].Port != 443 || ports[1].Port != 8443 {
		t.Errorf("expected sorted ports 443,8443, got %+v", ports)
	}
	for _, p := range ports {
		if p.Host == "admin.example.com" {
			t.Errorf("out-of-scope host leaked into port results")
		}
	}

	if got := argValue(passedArgs, "-top-ports"); got != "100" {
		t.Errorf("expected top-100 default, got %q", got)
	}
	if got := argValue(passedArgs, "-scan-type"); got != "c" {
		t.Errorf("expected connect scan, got %q", got)
	}
	if !hasArg(passedArgs, "-exclude-cdn") {
		t.Errorf("expected -exclude-cdn in naabu args, got %v", passedArgs)
	}
	if got := argValue(passedArgs, "-rl"); got != "10" {
		t.Errorf("expected -rl 10, got %q", got)
	}

	// Missing binary degrades gracefully.
	if ports, err := RunNaabu(context.Background(), NewMockRunner(), s, []string{"api.example.com"}, 100, 5, DefaultLog); err != nil || ports != nil {
		t.Errorf("expected nil result and nil error when naabu is missing, got %v, %v", ports, err)
	}
}

func TestRunNmapServiceScan(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedArgs []string
	calls := 0
	runner.RegisterTool("nmap", "/bin/nmap", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		calls++
		passedArgs = args
		output := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25.3"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>`
		return []byte(output), nil, nil
	})

	targets := []NmapTarget{
		{Host: "api.example.com", Ports: []int{443}},
		{Host: "admin.example.com", Ports: []int{22}},
	}
	results, err := RunNmapServiceScan(context.Background(), runner, s, targets, 5, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls != 1 {
		t.Errorf("expected nmap to run only for the in-scope host, got %d calls", calls)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 open port result, got %d", len(results))
	}
	if results[0].Service != "https" || results[0].Product != "nginx" || results[0].Version != "1.25.3" {
		t.Errorf("unexpected service fingerprint: %+v", results[0])
	}
	if !hasArg(passedArgs, "-sV") {
		t.Errorf("expected -sV in nmap args, got %v", passedArgs)
	}
	if got := argValue(passedArgs, "-p"); got != "443" {
		t.Errorf("expected explicit port list 443, got %q", got)
	}
}

func TestBuildHTTPXTargets(t *testing.T) {
	ports := []PortResult{
		{Host: "api.example.com", Port: 443},
		{Host: "api.example.com", Port: 8443},
		{Host: "api.example.com", Port: 443},
	}
	got := BuildHTTPXTargets([]string{"api.example.com"}, ports)
	want := []string{"api.example.com", "api.example.com:443", "api.example.com:8443"}
	if len(got) != len(want) {
		t.Fatalf("expected %d targets, got %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRunFFUF(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedArgs []string
	runner.RegisterTool("ffuf", "/bin/ffuf", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		passedArgs = args
		outPath := argValue(args, "-o")
		if outPath == "" {
			t.Errorf("expected -o output path in ffuf args, got %v", args)
			return nil, nil, nil
		}
		payload := `{"results":[
			{"url":"https://api.example.com/admin","input":{"FUZZ":"admin"},"status":200,"length":512,"words":10,"lines":2,"content-type":"text/html","redirectlocation":""},
			{"url":"https://admin.example.com/admin","input":{"FUZZ":"admin"},"status":403,"length":0,"words":0,"lines":0},
			{"url":"https://api.example.com/login","input":{"FUZZ":"login"},"status":302,"length":0,"words":0,"lines":0,"redirectlocation":"https://api.example.com/auth"}
		]}`
		if err := os.WriteFile(outPath, []byte(payload), 0644); err != nil {
			t.Errorf("write mock ffuf output: %v", err)
		}
		return nil, nil, nil
	})

	results, err := RunFFUF(context.Background(), runner, s, []string{"https://api.example.com"}, 3, 5, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 in-scope results, got %d: %+v", len(results), results)
	}
	if results[0].URL != "https://api.example.com/admin" || results[0].Status != 200 || results[0].Length != 512 {
		t.Errorf("unexpected first result: %+v", results[0])
	}
	if results[1].RedirectLocation != "https://api.example.com/auth" {
		t.Errorf("expected redirect location captured, got %+v", results[1])
	}
	if got := argValue(passedArgs, "-rate"); got != "3" {
		t.Errorf("expected -rate 3, got %q", got)
	}
	if got := argValue(passedArgs, "-w"); got == "" {
		t.Errorf("expected wordlist path, got %v", passedArgs)
	}
	if !strings.Contains(argValue(passedArgs, "-u"), "FUZZ") {
		t.Errorf("expected FUZZ template, got %q", argValue(passedArgs, "-u"))
	}
}

func TestRunFFUFSkipsQueryTargets(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()
	runner.RegisterTool("ffuf", "/bin/ffuf", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		t.Errorf("ffuf must not run against query-string targets")
		return nil, nil, nil
	})

	results, err := RunFFUF(context.Background(), runner, s, []string{"https://api.example.com/search?q=1"}, 3, 5, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no results, got %+v", results)
	}
}

func TestRunDalfox(t *testing.T) {
	s := createTestScope(t)
	runner := NewMockRunner()

	var passedArgs []string
	calls := 0
	runner.RegisterTool("dalfox", "/bin/dalfox", func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
		calls++
		passedArgs = args
		outPath := argValue(args, "--output")
		payload := `[{"type":"V","inject_type":"inHTML","poc":"https://api.example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E","evidence":"<script>alert(1)</script>","payload":"<script>alert(1)</script>","method":"GET","param":"q","cwe":"CWE-79","severity":"High"}]`
		if err := os.WriteFile(outPath, []byte(payload), 0644); err != nil {
			t.Errorf("write mock dalfox output: %v", err)
		}
		return nil, nil, nil
	})

	urls := []string{
		"https://api.example.com/search?q=test",
		"https://api.example.com/about",           // no parameters, must be skipped
		"https://admin.example.com/search?q=test", // out of scope
	}
	findingsList, err := RunDalfox(context.Background(), runner, s, urls, 3, 10, DefaultLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls != 1 {
		t.Errorf("expected exactly one dalfox invocation, got %d", calls)
	}
	if len(findingsList) != 1 {
		t.Fatalf("expected 1 candidate finding, got %d", len(findingsList))
	}

	f := findingsList[0]
	if f.CheckName != "dalfox" {
		t.Errorf("expected check name dalfox, got %q", f.CheckName)
	}
	if f.Confidence != findings.ConfidenceLow {
		t.Errorf("dalfox results must be low-confidence candidates, got %q", f.Confidence)
	}
	if f.Severity != findings.SeverityHigh {
		t.Errorf("expected high severity mapping, got %q", f.Severity)
	}
	if !hasArg(passedArgs, "--deep-domxss") {
		t.Errorf("expected --deep-domxss, got %v", passedArgs)
	}
	if got := argValue(passedArgs, "--worker"); got != "1" {
		t.Errorf("expected single worker, got %q", got)
	}
	if got := argValue(passedArgs, "--delay"); got != "333" {
		t.Errorf("expected delay derived from 3 rps (333ms), got %q", got)
	}
}

func TestDefaultPathWordlistIsCurated(t *testing.T) {
	wl := DefaultPathWordlist()
	if strings.TrimSpace(wl) == "" {
		t.Fatal("embedded path wordlist is empty")
	}
	lines := strings.Fields(strings.TrimSpace(wl))
	if len(lines) > 100 {
		t.Errorf("default path wordlist must stay curated, got %d entries", len(lines))
	}

	path, err := WritePathWordlist()
	if err != nil {
		t.Fatalf("WritePathWordlist: %v", err)
	}
	defer os.Remove(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read materialised wordlist: %v", err)
	}
	if strings.TrimSpace(string(data)) != strings.TrimSpace(wl) {
		t.Error("materialised wordlist differs from embedded wordlist")
	}
}
