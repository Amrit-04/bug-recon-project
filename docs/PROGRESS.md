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

---

## Milestone 3: Deterministic Validation Gate (`scoutr validate`) & Workspace Persistence ✅

### What Was Built

1. **Package `internal/validate` (The 7-Check Readiness Gate)**:
   - **Gate 1 (Scope Verification)**: Ensures target host and endpoint are strictly permitted by `scope.Scope`.
   - **Gate 2 (Soft-404 / Baseline Diff)**: Distinguishes genuine file exposures from single-page application (SPA) catch-all fallbacks and generic HTML 404 pages.
   - **Gate 3 (Content Signature Match)**: Enforces structural regex signatures on sensitive exposures (e.g. valid Git ref `ref: refs/heads/` or 40-hex commit hash for `.git/HEAD`; key-value assignments for `.env`; Apple magic header for `.DS_Store`).
   - **Gate 4 (Impact Classification)**: Identifies actionable security posture findings while classifying missing security headers on static assets (`.png`, `.css`, `.woff`) as `NeedsManualReview`.
   - **Gate 5 (Evidence Completeness & Credential Redaction)**: Verifies presence of reproducible evidence snippets and automatically redacts AWS keys (`AKIA...`), JWT tokens, and Bearer authorization tokens.
   - **Gate 6 (Deduplication & Root-Cause Grouping)**: Groups repetitive misconfigurations on the same host under a single primary finding with `AffectedPaths` aggregated.
   - **Gate 7 (Remediation Mapping)**: Maps findings to built-in knowledge base entries containing actionable remediation instructions, CWE identifiers, and OWASP references.
   - Findings categorized into `Verified`, `NeedsManualReview`, and `Suppressed`.

2. **Package `internal/workspace` (Audit Session Persistence)**:
   - Creates structured run directories under `.scoutr/runs/<target>-<timestamp>/`.
   - Persists and loads `inventory.json`, `raw_findings.json`, `validated_findings.json`, `report.md`, and `report.html`.
   - Supports both JSON arrays and JSONL stream decoding for offline resilience.

3. **Package `internal/report` & CLI Subcommands**:
   - `internal/report/markdown.go`: Generates executive-ready HackerOne/Bugcrowd structured Markdown reports with severity summaries, remediation guidance, and evidence blocks.
   - `internal/report/html.go`: Produces single-file interactive HTML reports with responsive layouts, collapsible `<details>` evidence drawers, and light/dark theme toggles.
   - `scoutr validate`: Supports direct evaluation via `-i` and offline re-validation via `--from <run-dir>`.
   - `scoutr report`: Supports offline report generation directly from `--from <run-dir>` without re-scanning.

### Go Patterns Used
- **Multi-Format Deserialization**: Workspace loaders test JSON array format (`[`) before falling back to line-by-line `bufio.Scanner` JSONL streaming, ensuring seamless interoperability between batch tools and unix pipes.
- **Data Aggregation & Grouping**: Map-based aggregation preserving insertion order via tracking keys (`orderedKeys`), cleanly deduplicating endpoints across identical rule IDs without data loss.
- **Embedded Static Assets & Templating**: Single-file HTML generation with self-contained CSS variables and vanilla JavaScript functions eliminating external CDN dependencies and security risks.

### Testing
- `TestGate1ScopeVerification`: Confirmed in-scope vs out-of-scope gate enforcement.
- `TestGate2And3Soft404AndSignatures`: Verified suppression of HTML SPA fallbacks pretending to be `.git/HEAD` or `.env`.
- `TestGate4ImpactClassification`: Verified downgrade of static asset header findings to `NeedsManualReview`.
- `TestGate5EvidenceRedaction`: Confirmed automated masking of AWS access keys and JWT strings.
- `TestGate6DeduplicationAndGrouping`: Verified grouping of multiple paths on the same host into one primary finding.
- `TestGate7RemediationMapping`: Verified automated mapping of CWE/OWASP references and remediation text.
- `TestWorkspaceLifecycle`: Verified end-to-end saving and loading of inventory, raw findings, validated findings, and reports across runs.
- `TestReportGeneration`: Verified Markdown and interactive HTML report generation.

---

## Milestone 4: Expanded Tier 1 Toolchain (naabu, nmap, ffuf, dalfox) ✅

### What Was Built

Four new active-scanning tools, each invoked with conservative read-only defaults and wired into the deterministic pipeline (`scoutr run`).

| Stage | Tool | Package / function | Conservative defaults | Artifact |
|-------|------|--------------------|-----------------------|----------|
| Port scan (after `dnsx`, before `httpx`) | `naabu` | `tools.RunNaabu` | `-top-ports 100` (or `1000` with `--top-ports 1000`, never 65535), `-scan-type c` (connect scan), `-exclude-cdn`, `-rl <rate>` | `ports.json` |
| Service/version detection (only on naabu-discovered ports) | `nmap` | `tools.RunNmapServiceScan` | `-sV --version-light -Pn -T3 --max-rate <rate> --max-retries 1 --host-timeout 60s -p <explicit ports>`, one host per invocation; never a broad scan | merged into `ports.json` (`Service`/`Product`/`Version`) |
| Live host fingerprint (feeds ports into httpx) | `httpx` | `tools.BuildHTTPXTargets` + `RunPDHTTPX` | `scheme://host:port` targets built only from in-scope discoveries | `httpx.json` |
| Content/path discovery (after `katana`) | `ffuf` | `tools.RunFFUF` | embedded 49-entry curated wordlist, `-mc 200,204,301,302,307,308,401,403,405`, `-t 5`, `-rate <per-host>`, `-timeout 10 -s -noninteractive`, max 25 targets per run | `fuzz.json` (status, length, words, lines, content-type, redirect location) |
| XSS with headless DOM verification (parameterised endpoints only) | `dalfox` | `tools.RunDalfox` | `url <target> --deep-domxss --format json --output <tmp> --silence --no-spinner --worker 1 --delay <1000/rate>`, max 50 targets | candidates appended to `raw_findings.json` (Confidence: `low`, never Verified) |

Supporting changes:

- `internal/findings`: added `SeverityCritical`; `RunNucleiPosture` now maps nuclei `critical` to `critical` instead of silently downgrading it to `info`.
- `internal/tools/tool.go`: new `TrustTierActiveScan` tier plus registry entries (and install hints) for naabu, nmap, ffuf, dalfox so `scoutr arsenal` reports them.
- `internal/tools/stages.go`: stage implementations. All go through `SafeToolExecution` / `FilterTargetsInScope` / `FilterDiscoveredItem`, so the three-layer scope enforcement is unchanged, and every loop checks `ctx.Err()` for cancellation.
- `internal/workspace`: `ports.json`, `httpx.json`, `crawl.json`, `fuzz.json` artifact helpers (`SaveArtifact`/`LoadArtifact`) with a plain-file-name guard.
- CLI: `scoutr ports` (naabu → optional nmap → optional httpx), `scoutr fuzz`, `scoutr xss`, and `scoutr run` now executes the full ordered pipeline: enum → dnsx → naabu → nmap → httpx → katana → ffuf → dalfox → nuclei → validate → report.
- `scripts/install_tools.sh` and `scripts/install_tools.ps1`: added naabu, ffuf and dalfox; nmap is package-manager installed only when explicitly requested (`--with-nmap` / `-WithNmap`).

### Testing
- `TestNormalizeTopPorts`: only 100 and 1000 are accepted; anything else falls back to 100.
- `TestRunNaabu`: verified `-top-ports 100`, `-scan-type c`, `-exclude-cdn` and `-rl` are always present.
- `TestRunNmapServiceScan`: verified `-sV` plus an explicit `-p` list and that out-of-scope hosts are never scanned.
- `TestBuildHTTPXTargets`: verified ports are folded into httpx targets.
- `TestRunFFUF` / `TestRunFFUFSkipsQueryTargets`: verified JSON parsing, post-filtering, `-rate` mapping and that query URLs are not fuzzed.
- `TestRunDalfox`: verified `--deep-domxss`, single worker, delay derived from the rate limit, and `low`-confidence candidates.
- `TestDefaultPathWordlistIsCurated`: the embedded ffuf wordlist stays small (≤100 entries).

---

## LLM Integration Architecture (Tier 2 triage/drafting, Tier 3 human gate)

### Tier separation

| Tier | Autonomy | Components |
|------|----------|------------|
| **Tier 0** | Autonomous | Passive recon (`crt.sh`, `subfinder`, `amass`, `assetfinder`, `dnsx`), workspace persistence, dedup/grouping |
| **Tier 1** | Autonomous (rate limited) | `httpx`, `katana`, `naabu`, `nmap`, `ffuf`, `dalfox`, `nuclei` (read-only tags), the 7-Check Readiness Gate |
| **Tier 2** | Agent-assisted | `internal/triage` (ranking), `internal/draft` (report drafting), `scoutr triage`, `scoutr report --draft` |
| **Tier 3** | Human only | State-changing requests, exploit payloads beyond standard probes, and submission: `scoutr submit --require-approval` |

The tiers are never collapsed: Tier 0/1 stages are a fixed sequence in `internal/cli/run.go` (code decides what runs next, not a model), Tier 2 only ranks and phrases, Tier 3 requires a keystroke.

### Pipeline sequence (code, not model)

```
enum → dnsx → naabu → nmap → httpx → katana → ffuf → dalfox → nuclei
     → 7-Check gate (raw_findings.json → validated_findings.json)
     → triage (validated_findings.json → triage.json)
     → report --draft (validated + triage → reports/drafts/*.md)
     → a human runs submit --require-approval and types APPROVE
```

### Files the LLM reads and writes

| Component | Reads | Writes |
|-----------|-------|--------|
| `scoutr triage` / `internal/triage` | `<run>/validated_findings.json`, `<run>/httpx.json` (technology only) | `<run>/triage.json` |
| `scoutr report --draft` / `internal/draft` | `<run>/validated_findings.json`, `<run>/triage.json`, `<run>/httpx.json` | `<run>/reports/drafts/<finding-id>.md`, `<run>/reports/drafts/index.md` |
| `scoutr submit --require-approval` | the draft, `<run>/validated_findings.json`, `<run>/triage.json` | `<run>/submission_ready.json` (local queue only) |

What the model actually receives per finding is a redacted evidence bundle built by `triage.BuildEvidence`: finding/template ID, target/path, severity, gate verdict and gate results, CWE, technology, impact, remediation, plus request/response excerpts passed through `validate.RedactEvidence` and truncated. Batches are 10–20 findings (default 12) per call, one structured JSON prompt, no free-text parsing.

`triage.json` is an ordering artifact only. `validated_findings.json` remains the report's source of truth; the Markdown/HTML report still renders from it alone.

### Hard-rule override layer (code, not model)

The model can only ever be overridden in the protective direction: `likely_false` → `needs_human`. `internal/triage/rules.go` applies three deterministic rules after every batch:

| Rule ID | Condition | Effect |
|---------|-----------|--------|
| `gate_verdict_verified` | the 7-Check gate returned `Verified` | keep the finding in the human queue |
| `severity_critical_or_high` | severity is `critical` or `high` | keep the finding in the human queue |
| `first_cwe_occurrence` | first finding of a CWE in this workspace | keep the finding in the human queue |

Overrides raise confidence to a floor of 50 and are recorded in `hard_rule_overrides` so the operator can see exactly why a small local model's judgement was rejected. Why this exists: a sub-9B model that confidently says “likely false” about a gate-Verified critical finding would otherwise bury it. Model failure, unparseable output, or `--no-llm` degrades every finding to `needs_human` — never to `likely_false`.

### Non-negotiables encoded in the code

1. **The LLM never sees the scope file.** There is no code path from `internal/triage` or `internal/draft` to `scope.Scope`, the YAML file, or the target inventory. Only redacted finding evidence is serialised into a prompt.
2. **The 7-Check gate remains the authority.** The gate writes `Verified` / `NeedsManualReview` / `Suppressed`; triage cannot change a verdict, and `Suppressed` findings are excluded from triage entirely and from the approval queue structurally.
3. **The scope guard is untouched.** All Tier 1 tools run through the existing pre/post filtering, and every HTTP request still goes through the `ScopedTransport` RoundTripper.
4. **No submission path.** `scoutr submit` has no platform client, no HTTP call, and `--require-approval` is mandatory; typing `APPROVE` only appends a local `submission_ready.json` entry. `Verified` and `NeedsManualReview` findings both pass through this gate.
5. **No invented evidence.** Draft evidence blocks are rendered by Go from `validated_findings.json`; model text is passed through URL/CWE/CVSS guards, and anything ungrounded becomes `NEEDS_HUMAN_INPUT`.

### Testing
- `internal/triage`: classification parsing (free text rejected), hard-rule overrides for Verified/high/first-CWE, batching sizes (`25 findings → 10/10/5`), suppression exclusion, deterministic degradation without a model, evidence redaction, host key normalisation, deterministic ranking.
- `internal/draft`: deterministic draft without a client, evidence copied verbatim, invented URL hosts and reproduction steps replaced, invalid CVSS/CWE rejected, free-text model output rejected, client failure degrades, file-name sanitisation.
- `internal/cli`: submit refuses without `--require-approval`, refuses without a draft, writes the queue entry only on exact `APPROVE`, ignores `approve`/`yes`, excludes suppressed findings from the queue, and requires `--finding` when several are pending.

---

## Milestone 5: Full-code review hardening

A whole-repository review (not just the new Tier 1/2 code) found three high-impact defects and ten smaller ones. All are fixed and covered by regression tests.

| ID | Defect | Fix |
|----|--------|-----|
| H1 | nuclei finding IDs were `NUC-<template>` only, so the same template on two hosts produced one ID that triage verdicts, drafts and the approval queue all joined on | IDs are now `NUC-<template>-<fnv32(target)>`; `triage.Run` also refuses a duplicate ID seen on a *different* target and records it in `llm_errors` |
| H2 | the model-supplied draft title bypassed the URL guard and became the H1 heading and a manifest cell | `guardSections` guards the title with the same host allowlist, collapses it to one line, rejects placeholders/fenced content/over-200-char titles, and falls back to the finding's own title; `render` prints the guarded `Draft.Title` |
| H3 | `scoutr scan` selected checks from a registry that is empty in this build and reported "Scan complete. Emitted 0 findings" | `scan` refuses to run when no checks are selected and `--verify-posture` is off; `[DRY-RUN]` output reports what would run. The registry itself was deleted in Milestone 6, so the guard now requires `--verify-posture` |
| M1 | `critical` severity was missing from both renderers (folded into Info in Markdown, `badge-info` in HTML) | Markdown gained a Critical row; HTML gained `badge-critical` and `--critical` |
| M2 | `validate.NewValidator(nil)` treated Gate 1 as passed, so `report -i` could mark findings Verified with no scope at all | Gate 1 now records `passed:false` ("Scope not configured") and downgrades to `NeedsManualReview`; `report` binds the validator to `--scope` when it is supplied |
| M3 | `engine.Pool.Process` started a second consumer that competed with the workers and could close `Results()` while workers were still sending | the handler is installed on the pool and executed by the workers; results are closed once, by `Wait`, after every worker stops; installing a handler after `Start` is rejected. The package had no callers and was removed in Milestone 6 |
| M4 | draft file-name collisions were silently renamed, but `submit` recomputes the name from the finding ID | a collision is now an error naming both findings; `index.md` is reserved |
| M5 | `submit` accepted a draft if its body contained the finding ID as a *substring* | it now requires the exact `Finding ID` manifest line for that ID, so `f-10` cannot approve `f-1` |
| L1 | `approved_by` read only Windows' `USERNAME` | `USER`, then `LOGNAME`, then `USERNAME` |
| L2 | `LoadInventory` did not tolerate a UTF-8 BOM while the other loaders did | same BOM trimming as the other readers |
| L3 | model-supplied `missing_fields` strings were rendered verbatim as bullets | whitelisted vocabulary, lowercased and de-duplicated; anything else is dropped with a guard warning |
| L4 | triage rationale / `next_manual_test` prose could name arbitrary hosts that were then displayed next to evidence | `triage.GuardURLs` rewrites any URL whose host is not in `triage.EvidenceHosts` (the drafting guard reuses it) |
| L5 | `mergeServiceFingerprints` appended nmap rows for ports naabu never reported, contradicting its own contract | unknown host/port rows are dropped |

Gap resolved in Milestone 6: the per-check package was empty scaffolding, so it was deleted rather than left in the tree advertising checks the binary cannot run. Built-in local checks remain a future milestone; `scan` is explicitly the `--verify-posture` command.

### Testing added in this milestone
- `internal/validate`: Gate 1 cannot pass without a scope file (status falls to `NeedsManualReview`).
- `internal/report`: `critical` findings appear in the Markdown summary and use `badge-critical` in HTML.
- `internal/draft`: the model title is guarded (invented host, injected heading) and `missing_fields` is whitelisted.
- `internal/triage`: duplicate IDs across targets are rejected; unverified hosts are stripped from rationale and manual-test prose.
- `internal/engine`: `Process` runs the handler for every task, surfaces handler errors, closes results on `Wait`, and rejects a late handler (the package was removed in Milestone 6; these guarantees are covered by the sequential pipeline instead).
- `internal/workspace`: `inventory.json` loads with a UTF-8 BOM in both array and JSONL layouts.
- `internal/cli`: draft filename collisions are refused, `mergeServiceFingerprints` keeps the naabu port set, and `scan` refuses to run without `--verify-posture`.

---

## Milestone 6: Production cleanup

Two subsystems were never wired into the CLI: the Phase-4 check registry had zero implementations, and the worker pool was referenced only by its own tests. Empty scaffolding that advertises capabilities the binary does not have is a production hazard, so both were deleted rather than kept "for later".

| Removed | Why |
|---------|-----|
| `internal/checks` (registry plus the empty `headers/cookies/exposure/takeover/cors/tls` directories) | no implementation, no production caller; the six checks in the help text did not exist |
| `internal/engine` (`Pool`, `Progress`, `DrainResults`) | no production caller; the pipeline is sequential and each external tool owns its own concurrency |
| `--checks`, `--skip`, and the `checks`/`skip_checks` config keys | they only fed the deleted registry; passing them now fails flag parsing instead of silently doing nothing |
| `--concurrency` and the `concurrency` config key | the value never bounded anything and only appeared in the banner; `--rate`/`--rate-per-host` are the enforced limits |
| `dump.rdb` (1.3 MB Redis dump at the repo root) | stray build artifact, unrelated to the tool (`.qoder/` is IDE-local and now ignored) |
| empty `internal/report/templates/` | HTML is rendered inline |

`scoutr scan` is now explicitly the opt-in nuclei posture command: `--verify-posture` is required, the help no longer lists checks that do not exist, and `scanPrecondition` refuses an inspection that would otherwise report a clean scan.

### Production hardening

- `.github/workflows/ci.yml` runs `make fmt-check`, `go vet`, `go build`, `go test` and the race detector on every push and pull request. `make ci` runs the same gate locally.
- README rewritten to describe what the binary actually does (scope guard, fixed pipeline, gate, triage, drafts, approval queue) and to list the built-in checks as a known limitation instead of a feature.
- `.gitignore` now covers `.qoder/`, `.scoutr/`, `reports/`, `dist/` and stray `*.rdb` files. `testdata/` is no longer ignored, so Go fixtures can be committed.
- `internal/triage/triage_test.go` had a duplicated `package` clause on disk (an IDE buffer flush re-introduced it); removed.

The ffuf path wordlist (`internal/tools/wordlist_paths.txt`) is `//go:embed`-ed and was restored after an over-eager cleanup; it is required, not stray.

### Wiring gaps closed in the same pass

- **`.scoutr.yaml` was documented but unreachable.** `config.LoadFromFile` had no caller and there was no `--config` flag. The loader is now reachable through `--config`, and precedence (flags > file > defaults) is enforced per key via `FileConfig.Apply(cfg, cmd.Flags().Changed)`, covered by `TestFileConfigApplyKeepsExplicitFlags`.
- **`probe` ignored the HTTP flags.** It built a new client per host with a hardcoded 10s timeout, no rate limiting, a fixed user agent, and an unused `Hosts` function. `probe.Hosts` now builds one scope-enforcing client from `Options` (timeout, max body, user agent, headers, global/per-host rate) and probes with bounded concurrency; the duplicated HTTPS/HTTP blocks were folded into `probeURL`. Tests: live probe with configured UA/header, input-order preservation, out-of-scope host rejected.
- **stdout was polluted.** The banner and per-command summaries were printed to stdout, so `scoutr enum ... | jq` received non-JSON lines. The banner (now printed after config merge, not on `--help`) and the summaries in `enum`, `crawl`, `probe`, `scan` and `urls` go to stderr; stdout is reserved for encoded results and reports.




