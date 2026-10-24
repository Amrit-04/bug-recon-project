# scoutr Development Progress

## Phase 1: Foundation - Scope, Config, HTTP Client with Rate Limiting ✅

### What Was Built

**1. Scope Package** (`internal/scope/scope.go`, `scope_test.go`)
- Parses scope YAML files with `in_scope` and `out_of_scope` entries
- Supports wildcard patterns: `*.example.com` matches `foo.example.com` and `a.b.example.com` but NOT `example.com` itself
- Out-of-scope always wins over in-scope (enforced precedence)
- Case-insensitive matching with port stripping
- Extensive unit tests covering wildcards, precedence, URL parsing

**Key Go Concept:** `scope.Checker` is a pure struct with no mutable state—all scope decisions are deterministic and thread-safe.

**2. Config Package** (`internal/config/config.go`, `config_test.go`)
- YAML config file parsing (`.scoutr.yaml`)
- Merges config file settings with command-line flags
- Precedence: flags > config file > built-in defaults
- Validation of all config values
- Tests for precedence, defaults, and validation

**Key Go Concept:** Pointers to primitive types (`*int`, `*float64`, `*string`) used in `FileConfig` to distinguish "not set" (nil) from "explicitly set to zero"—a common Go pattern for optional fields.

**3. HTTP Client Package** (`internal/httpx/client.go`, `client_test.go`)
- **Scope-enforcing RoundTripper:** Every request is checked against scope before sending
- **Redirect checking:** Out-of-scope redirects are blocked (via `http.Client.CheckRedirect`)
- **Dual rate limiting:** Both global (`--rate`) and per-host (`--rate-per-host`) token buckets using `golang.org/x/time/rate.Limiter`
- **Body size limiting:** Response bodies wrapped in `io.LimitReader` with configurable max (default 1 MB)
- **Dry-run mode:** `--dry-run` logs what would be sent without hitting the network
- **Custom User-Agent and headers:** Set via `--user-agent` and `--header` flags
- Tuned `http.Transport` with keep-alives and idle connection pooling

**Key Go Concepts:**
- **`http.RoundTripper` interface:** The `ScopedTransport` wraps the base transport to inject scope/rate-limit checks at the lowest level—impossible for any check module to bypass
- **`sync.Map` for per-host rate limiters:** Lock-free concurrent map for storing per-host limiter instances
- **Context threading:** `context.Context` passed through all rate-limit waits for clean shutdown on Ctrl+C

**Tests verify:**
- Out-of-scope requests are blocked before network I/O
- In-scope requests pass through
- Redirects to out-of-scope hosts are rejected
- Response bodies are truncated to max size
- Dry-run mode blocks out-of-scope but returns fake 200 for in-scope
- Custom User-Agent is set correctly
- Custom headers are applied
- Rate limiters respect token bucket semantics

**4. CLI Package** (`internal/cli/root.go`, `enum.go`, `probe.go`, `scan.go`, `report.go`, `run.go`)
- Root command with banner, banner printing, and graceful shutdown (Ctrl+C cancels `context.Context`)
- Subcommands: `enum`, `probe`, `scan`, `report`, `run` (stubs for later phases)
- Global flags for scope, output, format, concurrency, rate limiting, timeouts, etc.
- Per-command flags for input/output files
- Signal handling via `os.Signal` with context cancellation

**Key Go Concept:** Cobra's `PersistentFlags` are inherited by all subcommands—this keeps the CLI consistent without repeating flags.

**5. Placeholder Packages**
- `internal/recon/subdomains/subdomains.go`: Stubs for `FromCRTSH()` and `BruteForce()` (Phase 3)
- `internal/recon/probe/probe.go`: Stub for `Host()` (Phase 3)
- `internal/recon/subdomains/wordlist.txt`: Embedded default wordlist for DNS brute force (go:embed)

**6. Project Files**
- `Makefile`: build, test, lint, run, clean, release targets
- `testdata/scope_valid.yaml`: Sample scope file for testing
- `go.mod`, `go.sum`: Pinned dependencies

### Testing Results

**All Phase 1 tests pass:**
```
✅ internal/config: 6 tests pass
✅ internal/httpx: 10 tests pass (scope blocking, redirects, body limits, dry-run, rate limiting, headers)
✅ internal/scope: 5 tests pass (wildcards, precedence, URL parsing, case insensitivity)
```

**Build:** `go build ./cmd/scoutr` produces `scoutr.exe` with no errors or warnings

**Format & Vet:** `gofmt -w -s .` and `go vet ./...` pass with no issues

### Design Decisions

1. **Scope enforcement at transport level:** This makes it impossible for any check module to accidentally bypass scope—every request (including in redirects) is verified before leaving the machine.

2. **Rate limiters in ScopedTransport:** Global and per-host limiters are checked together in `RoundTrip()`, so they're guaranteed to be applied consistently to all requests.

3. **Body size limiting in transport:** Response bodies are wrapped immediately after receiving them, preventing any goroutine from accumulating unbounded data.

4. **No global state:** The `globalConfig` variable in `cli/root.go` is initialized once at startup and read-only after that—no race conditions.

5. **Context for shutdown:** All long-running operations accept `context.Context` so Ctrl+C cleanly cancels work without goroutine leaks.

6. **Dry-run as transport wrapper:** Rather than having every check module know about dry-run, the transport itself returns fake 200 responses, so the rest of the code is unchanged.

### Go Concepts Explained (For a Go Beginner)

**1. Interfaces and Implementation**
- `http.RoundTripper` is an interface: any type with a `RoundTrip(*http.Request) (*http.Response, error)` method implements it
- `ScopedTransport` implements `http.RoundTripper` by wrapping the real transport
- Go interfaces are implicit—no `implements` keyword needed

**2. Goroutines and Channels**
- `signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)` sends OS signals to a channel
- `go func() { <-sigCh; cancel() }` runs a goroutine that waits for a signal and cancels the context

**3. sync.Map for Concurrent Access**
- Per-host rate limiters are stored in `sync.Map`, which is optimized for high-concurrency read-heavy workloads
- `.Load(key)` and `.LoadOrStore(key, value)` are lock-free operations

**4. Rate Limiting with golang.org/x/time/rate**
- `rate.Limiter` is a token bucket: `Allow()` returns true if a token is available, `Wait()` blocks until one is
- Each limiter is tied to a `rate.Limit` (requests per second) and burst size
- Multiple limiters can protect different dimensions (global vs per-host)

**5. Context for Shutdown**
- `context.WithCancel(context.Background())` returns a context and a cancel function
- When `cancel()` is called, all operations waiting on that context are unblocked with `ctx.Err() == context.Canceled`
- This prevents goroutine leaks—no goroutine gets stuck waiting forever

### What's Not Yet Implemented

- Phase 2: Engine (worker pool, streaming pipeline)
- Phase 3: Recon (crt.sh passive enum, DNS brute force, host probing)
- Phase 4: Checks (headers, cookies, exposure, takeover, cors, tls)
- Phase 5: Reporting (Markdown/HTML generation)
- Phase 6: Integration tests, benchmarks, CI workflow

### How to Build and Test

```bash
# Build
make build

# Run tests
make test

# Format and lint
make lint

# Run the tool
./scoutr.exe --help

# Clean build artifacts
make clean
```

### Next: Phase 2

Phase 2 will build:
- Worker pool with bounded concurrency and clean shutdown
- Pipeline orchestration (orchestrates enum → probe → scan → report)
- Result streaming (JSONL output as results arrive, not buffered in memory)
- Progress indicator (cheap, TTY-aware, disabled when not a TTY)

This phase will also wire the CLI commands to the engine so `scoutr enum` and `scoutr probe` can run end-to-end.

---

## Phase 2: Engine - Worker Pool, Pipeline, Result Streaming ✅

### What Was Built

**1. Engine Package** (`internal/engine/pool.go`, `pipeline.go`, `progress.go`)
- **Bounded worker pool**: Configurable number of workers, bounded channels, no unbounded goroutines
- **Context-based shutdown**: `context.Context` threaded through all operations, clean shutdown on Ctrl+C
- **Graceful shutdown**: Workers drain current work and exit cleanly when context is cancelled
- **Result streaming**: Results written to output as they're found (JSONL), never buffered in memory
- **Progress indicator**: TTY-aware, updates on newline, no busy loops (uses `time.Ticker`)

**Key Go Concepts:**
- **Worker Pool Pattern**: A fixed number of goroutines read from a `tasks` channel and write to a `results` channel
- **Channels**: `tasks` channel for work items, `results` channel for results, `done` channel for completion signaling
- **sync.WaitGroup**: Ensures all workers finish before shutdown completes
- **Ticker for progress**: `time.Ticker` updates progress at fixed intervals without CPU spinning

**2. CLI Commands Wiring**
- `enum`: Reads scope, runs passive enum (crt.sh stub) and/or DNS brute force stub
- `probe`: Reads hosts from input, probes each with `probe.Host()` stub
- `scan`: Reads hosts from input, runs security checks stub
- `report`: Reads findings, generates report stub

**3. Finding Package** (`internal/findings/finding.go`)
- `Finding` struct with all required fields (ID, check name, target, severity, confidence, evidence, etc.)
- Severity enum: `Info`, `Low`, `Medium`, `High`
- Confidence enum: `Low`, `Medium`, `High`
- `Key()` method for deduplication (returns deterministic string for `(CheckID, Host, Path, Severity)`)

**4. Checks Registry** (`internal/checks/registry.go`)
- Global registry of checks with `Register()` and `GetAll()` functions
- `Check` interface: `ID()`, `Description()`, `Run(ctx, target, client)`
- Per-check enable/disable via `--checks` and `--skip` flags

### Testing

- Engine tests: worker pool shutdown, context cancellation, result streaming
- Finding tests: deduplication, severity/conformance enums
- Registry tests: registration, retrieval, filtering

### Next: Phase 3

Phase 3 will build:
- Passive subdomain enumeration via crt.sh API
- DNS brute force with wordlist and concurrent resolution
- Live host probing with status, title, headers, redirect chain

This phase will complete the `enum` and `probe` commands with real implementations.

---

## Milestone 1: `internal/tools` Runner Abstraction & `scoutr arsenal` ✅

### What Was Built

1. **Pure-Go Testable Runner Abstraction** (`internal/tools/runner.go`):
   - `CommandRunner` interface: `Run(ctx, bin, args, stdin)` and `LookPath(bin)`
   - `ExecRunner`: Production implementation leveraging `os/exec.CommandContext` with context timeouts and safe byte buffers
   - `MockRunner`: Deterministic pure-Go mock for unit testing across Windows and Linux CI without requiring external shell scripts or PATH binaries

2. **Safe Input/Output Handling & Three-Layer Scope Enforcement** (`internal/tools/tool.go`):
   - **Pre-filtering**: All targets pass `FilterTargetsInScope` with `scope.Scope` before invocation
   - **Post-filtering**: All discovered records, hosts, or URLs pass `FilterDiscoveredItem` before entering data structures
   - **Stdin & Temp File Modes**: Long target lists pass through stdin or temporary files (`defer os.Remove`), avoiding OS argument length limits
   - **Line-Safe Streaming Scanner**: `SafeLineScanner` with 1 MB maximum line buffer prevents memory exhaustion

3. **Arsenal Inspection & CLI** (`internal/cli/arsenal.go`):
   - `scoutr arsenal`: Inspects PATH for 9 supported tools, reporting installed status, version, and trust tiers (`Passive OSINT` vs `Read-Only Probe`)
   - `scripts/install_tools.ps1` & `scripts/install_tools.sh`: Manual installation scripts for operator-controlled setup via `go install`

### Go Patterns Used
- **Dependency Injection via Interfaces**: `CommandRunner` abstracts process execution, decoupling CLI commands from OS-level process spawning and enabling pure-Go unit testing.
- **Resource Cleanup via Defer**: `defer os.Remove(tmpPath)` guarantees cleanup of temporary input files even on unexpected returns or cancellations.
- **Bounded Streaming I/O**: `bufio.Scanner` with explicit buffer bounds prevents unbounded memory consumption when reading arbitrary external output.

### Testing
- `TestMockRunner`: Verified mock command dispatch, stdin capture, and error handling.
- `TestInspectArsenal`: Verified tool detection, version parsing, and trust tiers.
- `TestScopePreAndPostFiltering`: Verified out-of-scope targets are stripped before invocation and on discovery.
- `TestSafeToolExecutionStdin`: Verified stdin pipeline and out-of-scope target exclusion.
- `TestSafeToolExecutionTempFile`: Verified temp file creation, argument passing, and deferred deletion.

---

## Milestone 2: Wiring Passive & Read-Only Discovery Tools ✅

### What Was Built

1. **Passive & Read-Only Tool Integrations** (`internal/tools/discovery.go`, `discovery_test.go`):
   - **`subfinder`**: Passive subdomain discovery using `-silent -json`, stdin feeding, scope pre/post filtering.
   - **`amass`**: Strictly passive mapping via `enum -passive -nocolor -json`.
   - **`assetfinder`**: Passive subdomain correlation using `--subs-only`.
   - **`dnsx`**: DNS resolution and record verification with native `-rl <rate>` limit mapping.
   - **`httpx`** (ProjectDiscovery binary): Live host probe with title, webserver, tech stack, and status codes (`-silent -json -rl <rate> -no-color`). Zero package collision with internal `httpx.Client`.
   - **`waybackurls` / `gau`**: Passive historical archive endpoint retrieval with URL validation.
   - **`katana`**: Shallow web link discovery (`-silent -jsonl -rl <rate> -d 2`) with dynamic scope regex generation (`-cs` and `-cos`) derived from `scope.yaml`.
   - **`nuclei` (Strictly Read-Only/Informational Opt-In)**: Only invoked when `--verify-posture` is specified. Hardcodes read-only observation tags (`-tags ssl,tls,tech,headers,misconfig,exposure`), excludes invasive tags (`-etags fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf`), and enforces `-rl <rate>`, `-c 5`, and `-no-interactsh`.

2. **CLI Subcommands Wired**:
   - `scoutr enum --external`: Merges deduplicated, scope-verified results from `subfinder`, `amass`, `assetfinder`, and `dnsx` with built-in `crt.sh`.
   - `scoutr urls`: Retrieves and scope-filters historical URLs from public archive APIs.
   - `scoutr crawl`: Executes scope-constrained shallow link discovery.
   - `scoutr scan --verify-posture`: Opt-in read-only observation posture audit.
   - All commands feature comprehensive `--dry-run` support.

### Go Patterns Used
- **Graceful Tool Degradation**: External binaries are discovered via `LookPath`; missing tools log structured notices rather than failing execution.
- **Dynamic Regex Compilation**: Automated conversion of YAML scope patterns into valid Katana crawler regex boundaries (`BuildScopeRegex`).
- **Target Ingestion Streaming**: Line-by-line decoding of JSONL streams avoids loading unbounded result sets into memory.

### Testing
- `TestRunSubfinder`, `TestRunAmass`, `TestRunAssetfinder`: Verified passive subdomain extraction and post-filtering.
- `TestRunDNSX`: Verified rate limit argument mapping and DNS record filtering.
- `TestRunPDHTTPX`: Verified technology and status code parsing.
- `TestRunURLs`: Verified archive URL parsing across `gau` and `waybackurls`.
- `TestRunKatana`: Verified crawl depth, `-cs` / `-cos` scope regex arguments, and endpoint extraction.
- `TestRunNucleiPosture`: Verified mandatory read-only observation tags, `-no-interactsh`, and Finding mapping.


