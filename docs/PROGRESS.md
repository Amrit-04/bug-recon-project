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
