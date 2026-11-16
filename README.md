# scoutr

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
[![Security](https://img.shields.io/badge/Domain-AppSec%20%7C%20Bug%20Bounty-red?style=flat)](https://github.com/Amrit-04/bug-recon-project)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A scope-safe reconnaissance and validation CLI for authorized bug bounty and
penetration-testing work. Every HTTP request passes through a transport-level
scope guard; findings only reach a report after a deterministic readiness gate,
and nothing is ever submitted to a platform automatically.

## Pipeline

```
enum (subfinder/amass/assetfinder/crt.sh) -> dnsx -> naabu -> nmap -sV -> httpx
  -> katana -> ffuf -> dalfox -> nuclei (read-only posture) -> 7-check gate -> report
```

Each stage is fixed in Go (`internal/cli/run.go`); the order is not model-driven
and individual stages can be skipped with `--skip-<stage>` flags in `run`.

## Safety model

- **Scope guard**: YAML scope is enforced in `ScopedTransport.RoundTrip`,
  including redirects, and re-checked before and after every external tool.
- **Gate before report**: `internal/validate` assigns `Verified`,
  `NeedsManualReview` or `Suppressed`. A finding without a configured scope can
  never be `Verified`.
- **LLM is advisory**: `internal/triage` only ranks and phrases. It never sees
  the scope file or the target inventory and cannot change a gate verdict.
- **Human approval**: `scoutr submit --require-approval` prints the finding and
  requires a typed `APPROVE` before appending a local `submission_ready.json`
  entry. There is no platform API call anywhere in the codebase.

## Commands

| Command | Purpose |
|---------|---------|
| `scoutr enum` | Passive/brute-force subdomain enumeration |
| `scoutr probe` | Live host probing (status, title, headers, redirect chain) |
| `scoutr crawl` | Endpoint discovery with katana |
| `scoutr urls` | Fetch archived URLs (wayback/commoncrawl) |
| `scoutr ports` | naabu port discovery with optional nmap `-sV` |
| `scoutr fuzz` | Rate-limited content discovery with ffuf |
| `scoutr xss` | Read-only XSS candidate discovery with dalfox |
| `scoutr scan` | Opt-in nuclei read-only posture check (requires `--verify-posture`) |
| `scoutr validate` | Run the 7-check readiness gate over raw findings |
| `scoutr triage` | Tier-2 LLM triage over validated findings |
| `scoutr report` | Markdown/HTML/JSON reports; `--draft` writes evidence-derived drafts |
| `scoutr submit` | Interactive, local-only approval queue |
| `scoutr idor` | Candidate inventory extraction, differential testing, and reporting |
| `scoutr rce` | Execution sink discovery, multi-step chains, advisory correlation, and 3-profile validation |
| `scoutr ui` | Launch local web research dashboard & REST API on loopback |
| `scoutr run` | Full pipeline with workspace persistence |
| `scoutr arsenal` | Show external-tool availability and install hints |

All commands require `--scope <file>`; `--dry-run` shows what would be requested
without sending anything. Persistent flags can also be supplied in a YAML file
via `--config .scoutr.yaml`; explicit flags win over file values, and file values
win over defaults. Results go to stdout (or `-o`), all narration to stderr.

## Requirements

- Go 1.27
- Optional external tools, discovered on `PATH` (missing tools are skipped with a
  notice, never fatal): `subfinder`, `amass`, `assetfinder`, `dnsx`, `naabu`,
  `nmap`, `httpx`, `katana`, `ffuf`, `dalfox`, `nuclei`. See
  `scripts/install_tools.sh` / `scripts/install_tools.ps1`.
- Optional local LLM for triage: Ollama (`/api/chat`) or an OpenAI-compatible
  endpoint, configured with `--llm-*` flags; `--no-llm` forces deterministic
  degradation.

## Web Interface & Local API

Launch the unified browser-based dashboard with:

```bash
scoutr ui --scope scope.yaml [--port 8765]
```

The web dashboard provides:
- **Endpoints Explorer**: Deep route catalog, parameterized routes, query/body inspectors, and 1-click IDOR queueing.
- **IDOR Research Center**: Multi-tenant/dual-profile management, HAR file ingestion, candidate object reference extraction, and differential matrix visualization with reproduction evidence.
- **RCE Research Center**: Attack surface discovery across 6 execution sinks, multi-step processing chain tracking, curated CVE advisory correlation with 6-stage reachability progression, deterministic prioritization queue, and 3-profile validation (Passive, Safe Active marker probes, Manual plans).
- **Live SSE Streaming**: Real-time progress updates, background job management, and log telemetry.
- **Local API Security**: Binds strictly to loopback (`127.0.0.1`), enforces Host header validation, loopback CORS, 32-byte cryptographic session tokens (`X-Scoutr-Token`), anti-CSRF headers, path traversal guards, and OS-level ACLs (Windows `icacls`, Unix `0600`) for test credentials.

## Build, test, CI

```bash
make build                 # go build -o scoutr.exe ./cmd/scoutr
make test                  # go test ./... (all 19 packages)
make fmt-check             # fail if anything is not gofmt'd
make ci                    # fmt-check + vet + build + test (same gate as CI)

# Frontend Tests
npm --prefix web test      # run Vitest unit test suite (17 tests)
npm --prefix web run build # compile production web frontend bundle

# End-to-End Browser Tests
cd web && npx playwright test # run Playwright E2E browser test suite (7 workflows)
```

## Known limitations

- The built-in local checks (headers, cookies, exposure, takeover, CORS, TLS)
  are **not implemented**. `scoutr scan` therefore refuses to run without
  `--verify-posture` instead of reporting an empty, misleadingly clean scan.
- No platform submission, no exploit payloads, no model-driven tool selection.

See [docs/PROGRESS.md](docs/PROGRESS.md) for design decisions and the milestone
history.
