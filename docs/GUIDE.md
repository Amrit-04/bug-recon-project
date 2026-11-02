# scoutr — Operator Guide

| | |
|---|---|
| **Document ID** | DOC-GUIDE-001 |
| **Software** | scoutr v1.0 — scope-safe reconnaissance and validation CLI |
| **Module** | `github.com/scoutr/scoutr` |
| **Document version** | 1.0 (rev A) |
| **Verified against** | commit `f1dfb1b` (`main`); all code claims traced back to `5492ce9`, the last commit that touched Go sources |
| **Verified on** | Windows 11 26H2, `go1.27.0 windows/amd64`, PowerShell 5.1 |
| **Audience** | Bug-bounty hunters and pentesters doing authorized recon |
| **Source of truth** | This guide describes the code. Where it disagrees with the code, the code wins. |

> **Every number, flag and default in this document was read out of the source tree or
> produced by running the tool.** Section 19 lists the exact file and line for each claim.

---

## Table of contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Installation and build](#3-installation-and-build)
4. [The external arsenal](#4-the-external-arsenal)
5. [Scope file](#5-scope-file)
6. [Global flags and configuration](#6-global-flags-and-configuration)
7. [Command reference](#7-command-reference)
8. [The `run` pipeline](#8-the-run-pipeline)
9. [Per-tool command lines](#9-per-tool-command-lines)
10. [Data model](#10-data-model)
11. [The 7-Check Readiness Gate](#11-the-7-check-readiness-gate)
12. [Tier 2 — LLM triage](#12-tier-2--llm-triage)
13. [Tier 2 — report drafting](#13-tier-2--report-drafting)
14. [Tier 3 — human approval and submission](#14-tier-3--human-approval-and-submission)
15. [Workspace artifacts on disk](#15-workspace-artifacts-on-disk)
16. [Worked end-to-end session](#16-worked-end-to-end-session)
17. [Troubleshooting](#17-troubleshooting)
18. [Safety model and known limitations](#18-safety-model-and-known-limitations)
19. [References](#19-references)
20. [Revision history](#20-revision-history)

---

## 1. Overview

### 1.1 What scoutr is

scoutr is a **single binary** (`scoutr.exe`) that chains the standard bug-bounty recon
toolchain into one fixed pipeline, then puts a **deterministic quality gate** between
"tool said something" and "you put it in a report".

The pipeline, end to end:

```
enum (subfinder/amass/assetfinder/crt.sh) -> dnsx -> naabu -> nmap -sV -> httpx
  -> katana -> ffuf -> dalfox -> nuclei (read-only posture) -> 7-check gate -> report
```

### 1.2 What scoutr deliberately is not

| It is not | Consequence you will observe |
|---|---|
| An auto-submitter | No platform API call exists anywhere in the codebase. `submit` writes a local JSON file after you type `APPROVE`. |
| An exploit framework | Tier 1 tools run read-only with conservative budgets; Tier 3 actions (state-changing requests, payloads) are human-only by design. |
| An AI-driven agent | The stage order is a Go enum. No model, flag or config picks the next tool or the next target. |
| A fully-checked scanner | The built-in local checks (headers, cookies, exposure, takeover, CORS, TLS) are **not implemented**. `scan` therefore refuses to run without `--verify-posture` rather than printing a misleadingly clean result. |

### 1.3 The four tiers

| Tier | Nature | Members | Rule |
|---|---|---|---|
| **Tier 0** | Autonomous, zero traffic to target | passive recon, crt.sh, archives, persistence, dedup | safe to add freely |
| **Tier 1** | Autonomous at hard rate limits | `httpx`, `katana`, `naabu`, `nmap`, `ffuf`, `dalfox`, `nuclei` (read-only tags), the 7-Check gate | read-only defaults + scope filtering, mandatory |
| **Tier 2** | Agent-assisted, advisory only | `internal/triage`, `internal/draft` | may rank and phrase; may **never** change a gate verdict |
| **Tier 3** | Human only | state-changing requests, exploit payloads, submission | never automated |

---

## 2. Prerequisites

### 2.1 Required

| # | Requirement | Version | Verify command | Verified value |
|---|---|---|---|---|
| 1 | Go toolchain | 1.27.0 or newer | `go version` | `go1.27.0 windows/amd64` |
| 2 | Git (optional, for updates) | any | `git --version` | repo at `main`, `5492ce9` |
| 3 | GOPATH bin on PATH | — | `$env:Path -match 'go\\bin'` | `C:\Users\amrit\go\bin` present in both session and persistent user PATH |

`go.mod` declares `go 1.27.0`. There are **no runtime Go dependencies beyond five
modules**, all pulled from the module proxy — nothing is vendored:

| Module | Version | Used for |
|---|---|---|
| `github.com/spf13/cobra` | 1.10.2 | command tree |
| `github.com/spf13/pflag` | 1.0.9 | flag parsing |
| `github.com/inconshreveable/mousetrap` | 1.1.0 | Windows console-detach detection |
| `gopkg.in/yaml.v3` | 3.0.1 | scope + config files |
| `golang.org/x/time` | 0.16.0 | token-bucket rate limiting |

### 2.2 Optional

| # | Requirement | Needed for |
|---|---|---|
| 12 external binaries | §4 | stages degrade gracefully — a missing tool is **skipped with an `[INFO]` notice, never fatal** |
| Ollama or any OpenAI-compatible endpoint | §12 triage, §13 drafting | without it, pass `--no-llm`; every finding becomes `needs_human` |
| `make` | the `Makefile` targets | **not installed on this Windows host** — use the raw `go` commands in §3.2 |

---

## 3. Installation and build

### 3.1 Get the source

```powershell
git clone https://github.com/Amrit-04/bug-recon-project scoutr
cd s:\scoutr          # or your checkout path
```

### 3.2 Build and validate (raw Go — works everywhere)

```powershell
cd s:\bug-recon
go build -o scoutr.exe ./cmd/scoutr   # 1. compile
go vet ./...                          # 2. static analysis
go test ./... -count=1                # 3. full test suite
gofmt -l .                            # 4. must print nothing
```

Verified result on this host: build succeeds, `go vet` is silent, **all 9 test packages
pass** (`internal/recon/probe`, `report`, `scope`, `tools`, `triage`, `validate`,
`workspace`, `cli`, `config`), and `gofmt -l .` prints nothing.

### 3.3 The `Makefile` targets

| Target | Recipe | Note for Windows |
|---|---|---|
| `build` | `go build -o scoutr.exe ./cmd/scoutr` | `.exe` is hardcoded regardless of host OS |
| `test` | `go test -v ./...` | |
| `test-race` | `CGO_ENABLED=1 go test -race -v ./...` | needs cgo; this host has `CGO_ENABLED=0` |
| `lint` | `go vet ./...` + `gofmt -w -s .` | |
| `fmt-check` | POSIX `[ -n "$(...)" ]` guard | needs an `sh` shell, not bare PowerShell |
| `ci` | `fmt-check` → `vet` → `build` → `test -count=1` | the same gate as GitHub Actions |
| `run` | `./scoutr.exe --help` | |
| `clean` | removes `scoutr.exe`, `scoutr`, `go clean` | |
| `release` | cross-compiles 4 artifacts into `dist/` | linux-amd64, darwin-amd64, darwin-arm64, windows-amd64.exe |

`make` is absent on this host. Either use §3.2, or install it
(`winget install GnuWin32.Make`) and run `make ci` from **Git Bash** so the shell
conditionals in `fmt-check` evaluate.

### 3.4 Continuous integration

`.github/workflows/ci.yml` runs on `ubuntu-latest` for every push to `main`/`master`
and every PR: setup-go with `go-version-file: go.mod`, then **Format → Vet → Build →
Test → Test (race detector)**. The race job is the only step with no local Windows
equivalent here (§3.3).

---

## 4. The external arsenal

### 4.1 What the 13 tools are

Trust tier is what the code labels each binary, and it maps directly to §1.3.

| # | Tool | Trust tier | What it does | Upstream install command |
|---|---|---|---|---|
| 1 | `subfinder` | Passive OSINT | Subdomain discovery from passive sources | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| 2 | `amass` | Passive OSINT | In-depth attack-surface mapping (**passive mode only**) | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| 3 | `assetfinder` | Passive OSINT | Related domains/subdomains for a target | `go install github.com/tomnomnom/assetfinder@latest` |
| 4 | `waybackurls` | Passive OSINT | Historical URLs from the Wayback Machine | `go install github.com/tomnomnom/waybackurls@latest` |
| 5 | `gau` | Passive OSINT | Known URLs from AlienVault, Wayback, Common Crawl, URLScan | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| 6 | `dnsx` | Read-Only Probe | DNS resolution and record inspection | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| 7 | `httpx` | Read-Only Probe | HTTP probe: status, title, tech fingerprint | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| 8 | `katana` | Read-Only Probe | Shallow, scope-constrained crawl | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| 9 | `nuclei` | Read-Only Probe | Template scanner, locked to observation tags | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| 10 | `naabu` | Active Scan (Tier 1) | Port discovery, top-100 TCP connect | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| 11 | `nmap` | Active Scan (Tier 1) | `-sV` service detection on naabu's ports only | **not a Go binary** — `winget install Insecure.Nmap` |
| 12 | `ffuf` | Active Scan (Tier 1) | Content/path discovery, curated 49-entry wordlist | `go install -v github.com/ffuf/ffuf/v2@latest` |
| 13 | `dalfox` | Active Scan (Tier 1) | XSS probing with headless DOM verification | `go install -v github.com/hahwul/dalfox/v2@latest` |

### 4.2 Install them

**Windows (PowerShell):**

```powershell
.\scripts\install_tools.ps1              # the 12 Go binaries
.\scripts\install_tools.ps1 -WithNmap    # + nmap through winget (needs elevation)
```

**Linux/macOS:**

```bash
./scripts/install_tools.sh                # the 12 Go binaries
./scripts/install_tools.sh --with-nmap    # + nmap via apt-get/dnf/pacman/brew
```

### 4.3 Verified install result on this host

The script was run with `-WithNmap`. Result: **12 of 13 installed**, exit code 0.

| Tool | Status | Version reported by `arsenal` |
|---|---|---|
| subfinder | `[OK]` | 2.17.0 |
| amass | `[OK]` | 4.2.0 |
| assetfinder | `[OK]` | installed |
| dnsx | `[OK]` | 1.3.1 |
| httpx | `[OK]` | installed |
| waybackurls | `[OK]` | installed |
| gau | `[OK]` | 2.2.4 |
| katana | `[OK]` | 1.8.0 |
| nuclei | `[OK]` | 1.17 |
| naabu | `[OK]` | 2.7.0 |
| **nmap** | **`[MISSING]`** | — (winget aborted, `0x800704c7`, UAC dismissed) |
| ffuf | `[OK]` | 2.1.0-dev |
| dalfox | `[OK]` | 2.13.0 |

All binaries land in `C:\Users\amrit\go\bin`. Three tools report the literal string
`installed` instead of a version because their `-h`/`-version` output has no parsable
version token — that is cosmetic, not a failure.

### 4.4 Verify any time

```powershell
.\scoutr.exe arsenal --scope testdata\scope_valid.yaml
```

Prints a 4-column table (status, version, tier, manual install hint) plus the tier
summary. `arsenal` takes **no flags of its own** beyond the global set. Missing nmap
costs you only `Service`/`Product`/`Version` in `ports.json`; the stage logs
`[INFO] nmap not found on PATH, skipping service detection...` and continues.

---

## 5. Scope file

### 5.1 Format

Every command except `--help` requires `--scope <file>`. YAML, two keys:

```yaml
in_scope:
  - "example.com"
  - "*.example.com"
out_of_scope:
  - "admin.example.com"
  - "internal.example.com"
```

A working template is committed at `testdata\scope_valid.yaml`, and
`scope.yaml` at the repo root mirrors it with a placeholder target.

| Key | Meaning |
|---|---|
| `in_scope` | Hosts/patterns you are authorized to touch. `*.domain.com` matches subdomains. |
| `out_of_scope` | Carve-outs that win over `in_scope` — the program's "don't test this" list. |

### 5.2 How the guard is enforced

1. **Transport layer.** Every request made by scoutr's own HTTP client passes
   `ScopedTransport.RoundTrip` in `internal/httpx/client.go` — including **redirects**.
2. **Pre-filter.** Before any binary is launched, targets go through
   `FilterTargetsInScope`.
3. **Post-filter.** After parsing tool output, every discovered item passes
   `FilterDiscoveredItem`. Both directions matter: a tool that prints an out-of-scope
   host gets it dropped before it is ever stored.
4. **Gate 1.** A finding with no configured scope can never be `Verified` — see §11.

There is no flag, env var or config key that weakens this, by project rule.

### 5.3 Practical rules

- Put the **exact** domains from the program's policy page in `in_scope`. Do not add
  the parent TLD "just in case" — that is how people test assets they don't own.
- Anything with a blanket exclusion in the policy (employee portals, staging,
  third-party SaaS) belongs in `out_of_scope`.
- `scope.yaml` is **not** in `.gitignore` (only `.scoutr/` and `reports/` are). Do not
  commit a real target if the repo is public.

---

## 6. Global flags and configuration

### 6.1 Persistent flags (all 16)

These are defined once on the root command and inherited by every subcommand.

| # | Flag | Type | Default | Purpose |
|---|---|---|---|---|
| 1 | `--scope` | string | *(empty, required)* | Path to scope YAML |
| 2 | `--config` | string | *(none)* | Path to a `.scoutr.yaml` file |
| 3 | `-o`, `--output` | string | stdout | Output file |
| 4 | `-f`, `--format` | string | `jsonl` | `jsonl`, `md`, `html` |
| 5 | `--no-color` | bool | `false` | Disable ANSI colour |
| 6 | `-v`, `--verbose` | bool | `false` | Verbose narration (also enables tool `LogFunc` output) |
| 7 | `--dry-run` | bool | `false` | Show what would be requested, send nothing |
| 8 | `--rate` | float | `10.0` | Global requests/second |
| 9 | `--rate-per-host` | float | `3.0` | Per-host requests/second |
| 10 | `--timeout` | duration | `30s` | Request timeout |
| 11 | `--max-body` | int64 | `1048576` | Max response body bytes read (1 MiB) |
| 12 | `--user-agent` | string | *(empty → `scoutr/1.0`)* | Custom UA |
| 13 | `--header` | string→string | *(none)* | `--header X-Bug-Bounty:myhandle` |
| 14 | `--passive-only` | bool | `false` | No DNS brute force |
| 15 | `--brute` | bool | `false` | Enable DNS brute force (needs a wordlist) |
| 16 | `--wordlist` | string | *(none)* | Override the embedded wordlist |

*(14–16 only affect `enum`.)*

### 6.2 The config file

`--config .scoutr.yaml` accepts exactly 8 keys:

```yaml
rate: 5.0
rate_per_host: 2.0
timeout: "30s"          # string, e.g. "45s"
max_body_bytes: 524288
user_agent: "my-handle-recon"
headers:
  X-Bug-Bounty: myhandle
external: true
verify_posture: true
```

**Precedence: explicit flag > config file > built-in default.** The merge happens in
`PersistentPreRunE` using `cmd.Flags().Changed`, so a flag left at its default but set
in the file still applies. After the merge, `Config.Validate()` runs and aborts the
command on an invalid value.

### 6.3 Output convention

**stdout is data. stderr is narration.** The banner, progress lines, stage summaries
and warnings all go to stderr; JSONL and report payloads go to stdout (or `-o`). That
means this is safe:

```powershell
.\scoutr.exe enum --scope scope.yaml -o subs.jsonl        # file
.\scoutr.exe enum --scope scope.yaml | Select-Object -First 5   # pipe, no banner noise
```

PowerShell may surface stderr as a red `NativeCommandError` and report exit code 1 even
when the command succeeded. That is a shell artefact — check the actual output.

---

## 7. Command reference

14 commands. `run`, `enum`, `probe`, `scan`, `report` are registered on the root
command; the other 9 self-register from their own `init()`.

### 7.1 `enum` — subdomain enumeration

| | |
|---|---|
| **Purpose** | Enumerate in-scope subdomains, passively and/or by DNS brute force |
| **Own flags** | `--external` (bool, `false`) — merge subfinder/amass/assetfinder/dnsx |
| **Passive built-ins** | crt.sh certificate-transparency lookup |
| **Brute force** | `--brute`, embedded wordlist of **113 entries**, or `--wordlist file.txt` |
| **Output** | JSONL, one subdomain record per line |

```powershell
scoutr enum --scope scope.yaml -o subs.jsonl
scoutr enum --scope scope.yaml --passive-only -o passive.jsonl
scoutr enum --scope scope.yaml --external -o subs.jsonl
scoutr enum --scope scope.yaml --brute --wordlist subs.txt -o brute.jsonl
```

### 7.2 `probe` — live host probing

| | |
|---|---|
| **Purpose** | Which hosts are live; status code, title, `Server` header, tech hints, redirect chain |
| **Own flags** | `-i`, `--input` (JSONL file; stdin also accepted) |
| **Transport** | scoutr's own scope-enforcing client, so `--rate`, `--rate-per-host`, `--timeout`, `--user-agent`, `--header` all apply |

```powershell
scoutr probe --scope scope.yaml -i subs.jsonl -o live.jsonl
Get-Content subs.jsonl | scoutr probe --scope scope.yaml -o live.jsonl
```

### 7.3 `urls` — historical endpoints

| | |
|---|---|
| **Purpose** | Archived URLs from `gau` (AlienVault, Wayback, Common Crawl, URLScan) and `waybackurls` |
| **Own flags** | **none** — global set only |
| **Traffic to target** | **Zero.** Archive APIs only. Every returned URL is scope-filtered before output |

```powershell
scoutr urls --scope scope.yaml -o urls.jsonl
scoutr urls --scope scope.yaml --dry-run
```

### 7.4 `ports` — port discovery + service detection

| | |
|---|---|
| **Purpose** | `naabu` top-ports scan, then `nmap -sV` on exactly those ports |
| **Own flags** | `-i` input JSONL · `--from <run-dir>` · `--top-ports` (100 default, 1000 opt-in) · `--skip-service-detection` · `--probe` (feed results into httpx) |
| **Budget rule** | Anything other than 100 or 1000 is normalised back to 100 with a `[WARN]` |

```powershell
scoutr ports --scope scope.yaml -i live.jsonl --top-ports 1000 -o ports.json
scoutr ports --scope scope.yaml --from .scoutr\runs\example.com-20261102-120000 --probe
```

### 7.5 `crawl` — link discovery

| | |
|---|---|
| **Purpose** | Shallow, scope-constrained crawling via `katana` |
| **Own flags** | `-i` input hosts/URLs · `--depth` (default **2**) |
| **Scope mechanism** | The YAML scope is compiled into regexes passed as katana's `-cs` (crawl-scope) and `-cos` (crawl-out-of-scope) |

```powershell
scoutr crawl --scope scope.yaml -i live.jsonl --depth 3 -o crawl.json
```

### 7.6 `fuzz` — content discovery

| | |
|---|---|
| **Purpose** | `ffuf` against a **curated 49-path wordlist** (`admin`, `api`, `backup`, `config`, `.git`…) |
| **Own flags** | `-i` live hosts/URLs · `--from <run-dir>` (reads `httpx.json`, writes `fuzz.json`) · `--max-targets` (default **25** hosts) |
| **Match codes** | `200,204,301,302,307,308,401,403,405` — interesting but harmless responses only |
| **Output status** | **Candidates, not findings.** Everything must clear the gate |

```powershell
scoutr fuzz --scope scope.yaml -i live.jsonl --max-targets 10 -o fuzz.json
scoutr fuzz --scope scope.yaml --from .scoutr\runs\<run-dir>
```

### 7.7 `xss` — XSS candidate discovery

| | |
|---|---|
| **Purpose** | `dalfox` with `--deep-domxss` headless DOM verification on parameterised endpoints |
| **Own flags** | `-i` parameterised URLs · `--from <run-dir>` (reads `crawl.json`/`fuzz.json`, **appends** to `raw_findings.json`) · `--max-targets` (default **50** endpoints) |
| **Concurrency** | Hard-locked to **1 worker**, per-request delay derived from `--rate-per-host` (`1000/rph` ms, floor 100 ms) |

```powershell
scoutr xss --scope scope.yaml -i urls.jsonl --max-targets 20
scoutr xss --scope scope.yaml --from .scoutr\runs\<run-dir>
```

### 7.8 `scan` — read-only posture check

| | |
|---|---|
| **Purpose** | `nuclei` with safe observation tags only |
| **Own flags** | `-i` input · `--verify-posture` (bool) |
| **Hard precondition** | **Refuses to run without `--verify-posture`.** The built-in checks are not compiled into this build, so an opt-out run would inspect nothing and print a clean result — the code rejects that instead |
| **Enabled tags** | `ssl,tls,tech,headers,misconfig,exposure` |
| **Excluded tags** | `fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf` · `-no-interactsh` is forced |

```powershell
scoutr scan --scope scope.yaml -i live.jsonl --verify-posture -o findings.jsonl
```

### 7.9 `validate` — the 7-Check gate standalone

| | |
|---|---|
| **Purpose** | Run the readiness gate over raw findings |
| **Own flags** | `--from <run-dir>` (reads `raw_findings.json`) · `-i` JSONL file · `--triage` (chains Tier 2 after the gate, requires `--from`) + the LLM set (§12.3) |
| **Output** | `validated_findings.json` / JSONL with `status` + per-gate `gate_results` |

```powershell
scoutr validate --scope scope.yaml --from .scoutr\runs\<run-dir>
scoutr validate --scope scope.yaml -i findings.jsonl --triage --no-llm
```

### 7.10 `triage` — Tier 2 ranking

Covered in §12. `--from`, `-i`, `--batch-size` (default 12, max 20),
`--explain-rules`, plus the LLM flags.

### 7.11 `report` — reports and drafts

| | |
|---|---|
| **Purpose** | Render validated findings; or write per-finding submission drafts |
| **Own flags** | `--from <run-dir>` · `-i` findings JSONL · `--format md|html|jsonl` · `--draft` (Tier 2, requires `triage.json`) + LLM flags |
| **Formats** | `md` — HackerOne/Bugcrowd-structured · `html` — self-contained, light/dark toggle · `jsonl` — raw stream |
| **Guarantee** | `--draft` never overwrites the validated-findings report and never writes outside `reports/drafts/` |

```powershell
scoutr report -i validated.jsonl --format md   -o report.md
scoutr report -i validated.jsonl --format html -o report.html
scoutr report --from .scoutr\runs\<run-dir> --format html
scoutr report --from .scoutr\runs\<run-dir> --draft --no-llm
```

### 7.12 `submit` — Tier 3 approval queue

Covered in §14. `--from`, `--finding`, `--require-approval`, `--list`.

### 7.13 `run` — the full pipeline

Covered in §8.

### 7.14 `arsenal` — tool inventory

Covered in §4.4.

---

## 8. The `run` pipeline

### 8.1 Stage order (fixed in Go, not model-driven)

| # | Stage | Engine | What it does | Skip flag |
|---|---|---|---|---|
| 1 | enum | crt.sh + `--external` tools | Passive subdomains | `--skip-ports`-adjacent only |
| 1b | dnsx | `dnsx` | Resolve the enumerated names | — |
| 2 | ports | `naabu` → `nmap -sV` | Top-100 connect scan, then service detection on those ports | `--skip-ports`, `--skip-nmap` |
| 3 | probe | `httpx` | Live hosts, enriched with discovered ports | — |
| 4 | crawl | `katana` | Shallow scope-constrained link discovery | `--skip-crawl` |
| 5 | fuzz | `ffuf` | Curated path discovery, candidates only | `--skip-fuzz` |
| 6 | xss | `dalfox` | `--deep-domxss` on parameterised endpoints | `--skip-xss` |
| 7 | nuclei | `nuclei` | Read-only posture templates | `--skip-nuclei` |
| 8 | validate | 7-Check gate | Verdicts + artifact persistence | — |

### 8.2 `run` own flags

| # | Flag | Default | Meaning |
|---|---|---|---|
| 1 | `--external` | `false` | Merge external passive tools into stage 1 |
| 2 | `--top-ports` | `100` | Port budget: 100 or 1000 only |
| 3 | `--depth` | `2` | katana max crawl depth |
| 4 | `--max-fuzz-targets` | `25` | Host cap for ffuf |
| 5 | `--skip-ports` | `false` | Skip naabu + nmap |
| 6 | `--skip-nmap` | `false` | Skip service detection only |
| 7 | `--skip-crawl` | `false` | Skip katana |
| 8 | `--skip-fuzz` | `false` | Skip ffuf |
| 9 | `--skip-xss` | `false` | Skip dalfox |
| 10 | `--skip-nuclei` | `false` | Skip nuclei |

### 8.3 Verified dry-run output

```
[DRY-RUN] Scope file: scope.yaml (in_scope: [example.com *.example.com])
[DRY-RUN] Pipeline target: example.com
[DRY-RUN] Stages: enum -> dnsx -> naabu(top 100) -> nmap -sV -> httpx -> katana(depth 2)
                   -> ffuf(cap 25) -> dalfox -> nuclei(read-only) -> validate(7-check)
```

Three behaviours worth knowing:

1. **`--dry-run` returns before the workspace is created.** `Test-Path .scoutr` is
   `False` after a dry run — no `validated_findings.json`, no `report.md`. Artifacts
   require a live run.
2. **The printed stage list is static.** It shows `nmap -sV` even when nmap is missing,
   because the plan text is not tool-aware; the skip happens at execution.
3. **`--external` does not change the printed plan.** It only affects stage-1 merging
   once running.

### 8.4 Tier boundary

`run` deliberately stops at stage 8. Tier 2 and Tier 3 are separate explicit commands:

```powershell
scoutr triage --from <run-dir>
scoutr report --draft --from <run-dir>
scoutr submit --require-approval --from <run-dir>
```

---

## 9. Per-tool command lines

Exactly what scoutr passes to each binary. This is the useful section when a stage
behaves unexpectedly and you want to reproduce it by hand. Targets are always fed by
**stdin**, except nuclei which uses a cleaned **temp file** with `-l` (avoids Windows
command-length limits).

| Tool | Command line scoutr executes |
|---|---|
| subfinder | `subfinder -silent -json` |
| amass | `amass enum -passive -nocolor -json` |
| assetfinder | `assetfinder --subs-only` |
| dnsx | `dnsx -silent -json -rl <rate>` |
| httpx | `httpx -silent -json -no-color -rl <rate>` |
| gau | `gau --json` |
| waybackurls | `waybackurls` — executed with **no flags at all**, domains via stdin, run after gau in the same `RunURLs` call |
| naabu | `naabu -silent -json -top-ports <100\|1000> -scan-type c -exclude-cdn -rl <rate>` |
| nmap | `nmap -sV --version-light -Pn -T3 --max-rate <rate×10, min 10> --max-retries 1 --host-timeout 60s -p <explicit ports> -oX - <host>` |
| katana | `katana -silent -jsonl -d <depth> -no-color -rl <rate> -cs <scope-regex> -cos <exclusion-regex>` |
| ffuf | `ffuf -u <template> -w <wordlist> -of json -o <out> -mc 200,204,301,302,307,308,401,403,405 -t 5 -rate <rate> -timeout 10 -s -noninteractive` |
| dalfox | `dalfox url <target> --deep-domxss --format json --output <out> --silence --no-spinner --worker 1 --delay <ms> --timeout 10` |
| nuclei | `nuclei -silent -jsonl -no-interactsh -c 5 -rl <rate> -tags ssl,tls,tech,headers,misconfig,exposure -etags fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf -l <tempfile>` |

### 9.1 The safety numbers, in one place

| # | Constant | Value | Why it matters |
|---|---|---|---|
| 1 | `DefaultNaabuTopPorts` | **100** | Default port budget; 65,535 is unreachable |
| 2 | `AlternateNaabuTopPorts` | **1000** | The only wider option |
| 3 | `DefaultMaxFFUFTargets` | **25** | Host cap for content discovery |
| 4 | `DefaultMaxDalfoxTargets` | **50** | Endpoint cap for XSS probing |
| 5 | ffuf match codes | **9 codes** | Excludes noisy/`404` bodies |
| 6 | ffuf threads | **5** | `-t 5`, rate-limited on top |
| 7 | dalfox workers | **1** | Serialized on purpose |
| 8 | dalfox delay | **1000 ÷ rate-per-host ms, floor 100** | 3 rph → 333 ms |
| 9 | nmap `--max-rate` | **rate × 10, floor 10** | Derived from your rate, never left to nmap |
| 10 | nmap `--host-timeout` | **60s** | One host per invocation, always |
| 11 | nuclei concurrency | **`-c 5`** | Fixed, plus `-rl` |
| 12 | Fallback internal rate | **5/s** (naabu, nmap, nuclei), **3/s** (ffuf, dalfox) | Applied if rate ≤ 0 |
| 13 | Tool output line buffer | **1 MiB** | `MaxScanLineBytes`, prevents huge-line crashes |
| 14 | Embedded DNS wordlist | **113 entries** | `subdomains/wordlist.txt` |
| 15 | Embedded path wordlist | **49 entries** | `tools/wordlist_paths.txt` |

### 9.2 Why naabu needs no admin rights on Windows

`-scan-type c` is hardcoded — TCP **connect** scanning, not SYN. No raw sockets, no
Npcap, no elevation. The trade-off is slower and less stealthy probing, which is the
correct side of the safety line for a tool that runs autonomously.

---

## 10. Data model

### 10.1 `Finding` — the raw unit of evidence

Serialized as JSONL. Fields verified in `internal/findings/finding.go`:

| # | Field | JSON key | Type | Notes |
|---|---|---|---|---|
| 1 | ID | `id` | string | **required** |
| 2 | CheckName | `check_name` | string | **required** |
| 3 | RuleID | `rule_id` | string | optional; nuclei template ID, etc. |
| 4 | Target | `target` | string | **required** — host or URL |
| 5 | Path | `path` | string | optional |
| 6 | Title | `title` | string | |
| 7 | Severity | `severity` | enum | `info` `low` `medium` `high` `critical` |
| 8 | Confidence | `confidence` | enum | `low` `medium` `high` |
| 9 | Evidence | `evidence` | string | trimmed request/response snippet, redacted at gate 5 |
| 10 | Request | `request` | string | replayable curl |
| 11 | Response | `response` | string | response snippet |
| 12 | Impact | `impact` | string | |
| 13 | Remediation | `remediation` | string | gate 7 |
| 14 | References | `references` | []string | CWE / OWASP links, gate 7 |
| 15 | Timestamp | `timestamp` | RFC3339 | |

### 10.2 Dedup key

`Finding.Key()` is deterministic, which is what gate 6 groups on:

```
with RuleID:  check_name:rule_id:target:path:severity
without:      check_name:target:path:severity
```

### 10.3 `ValidatedFinding` — finding + verdict

| Field | JSON key | Meaning |
|---|---|---|
| Finding | `finding` | the embedded raw finding |
| Status | `status` | `Verified` \| `NeedsManualReview` \| `Suppressed` |
| GateResults | `gate_results` | up to **7** entries, one per gate |

Each `GateResult` is `{ gate_id, name, passed, reason }`. `reason` is only present on a
failure, so a passing gate costs no bytes in the artifact.

### 10.4 Verdict lifecycle

```
raw finding --gate--> Verified ----------> (still needs a human) --submit APPROVE--> submission_ready
                    |- > NeedsManualReview -> human verifies by hand
                    \-> Suppressed           (confirmed FP / out-of-scope / soft-404)
```

`ValidateFinding` starts every finding at `Verified` and **only ever downgrades it**.
There is no code path that upgrades a finding into `Verified`.

---

## 11. The 7-Check Readiness Gate

The deterministic authority in `internal/validate`. This — not a model — decides
whether something reaches your report.

| # | Gate name | What it tests | On failure |
|---|---|---|---|
| 1 | **Scope Verification** | No scope configured → status cannot be verified. Target outside scope | `Suppressed`; with no scope file it is blocked from `Verified` |
| 2 | **Soft-404 / Baseline Diff** | Response is an HTML page / SPA fallback instead of the raw file; or the server returns `200` for a non-existent baseline path | `Suppressed` |
| 3 | **Content Signature Match** | `.git/HEAD` must contain `ref: refs/heads/...` or a 40-hex commit hash · `.env` must hold `KEY=value` and must not look like HTML · `.DS_Store` must carry its 4-byte magic header | `Suppressed` |
| 4 | **Impact Classification** | Missing security headers on a static asset path (`.png`, `.css`, `.woff`) are informational, not a report | `NeedsManualReview` |
| 5 | **Evidence Completeness** | Evidence is redacted first (`RedactEvidence`), then must still contain a request/response or extracted snippet | blocks `Verified` → downgraded |
| 6 | **Deduplication & Grouping** | Cross-finding grouping on `Finding.Key()` (§10.2); passes at the individual level | passes per finding |
| 7 | **Remediation Mapping** | Needs non-empty `remediation` **and** at least one `references` entry. `LookupRemediation(check_name, rule_id, title)` auto-fills gaps first | `NeedsManualReview` |

### 11.1 Reading a failure

| Reason text you will see | What it means | What to do |
|---|---|---|
| `Target X is outside permitted scope` | Gate 1 — tool reported a host not in `in_scope` | Fix `scope.yaml`, or accept that it was right to drop it |
| `No scope file configured: in-scope status could not be verified` | Gate 1 | Always pass `--scope` |
| `Endpoint returned HTML page / SPA fallback instead of raw file` | Gate 2 — classic soft-404 | Confirm manually before believing it |
| `Server returns HTTP 200 for non-existent baseline paths` | Gate 2 — wildcard 200s | Treat every path finding from this host as suspect |
| `does not contain valid ref:` / `missing 4-byte magic header` | Gate 3 — the file is a decoy | Almost certainly a false positive |
| `Missing security headers on non-sensitive static asset path` | Gate 4 | Re-check on a real page |
| `Finding does not have remediation or CWE/OWASP references` | Gate 7 | Add remediation/references; a report-quality requirement, not a formality |

---

## 12. Tier 2 — LLM triage

### 12.1 What it may and may not do

| May | May not |
|---|---|
| Rank findings | Change a gate verdict |
| Phrase a rationale | Mark something `suppressed` |
| Flag ambiguity for a human | Promote something to `Verified` |
| Order the queue | Decide which tool runs next, or which target gets scanned |

`triage.json` **only affects ordering.** `validated_findings.json` stays the source of
truth for every report.

### 12.2 Classifications and guarantees

| Value | Meaning |
|---|---|
| `likely_true` | Supplied evidence strongly supports a real issue |
| `likely_false` | Evidence strongly suggests a non-issue |
| `needs_human` | Insufficient or ambiguous evidence |

Three verified behaviours, each covered by a test in `internal/triage/triage_test.go`:

1. **Structured JSON only.** A free-text model reply is *not trusted* — the verdict
   degrades to `needs_human`.
2. **No model, no crash.** `--no-llm` (or no client) yields `needs_human` for
   everything, deterministically.
3. **Hard rules can only rescue, never bury.** A gate-`Verified`, critical/high or
   first-of-its-CWE finding cannot stay `likely_false`.

### 12.3 The three deterministic hard rules

The only permitted override direction is `likely_false -> needs_human`, applied in code
outside the model:

| # | Rule ID (persisted in `triage.json`) | Fires when |
|---|---|---|
| 1 | `gate_verdict_verified` | The 7-Check gate returned `Verified` |
| 2 | `severity_critical_or_high` | Severity is `critical` or `high` |
| 3 | `first_cwe_occurrence` | First finding of this CWE class in the workspace |

When a rule fires, the verdict gains `hard_rule_overrides`, its confidence is floored at
**50**, and `source` becomes `llm+hard_rule`. Print the same text from the binary:

```powershell
.\scoutr.exe triage --explain-rules
```

### 12.4 Numbers

| # | Constant | Value |
|---|---|---|
| 1 | `DefaultBatchSize` | **12** findings per LLM call |
| 2 | `MaxBatchSize` | **20** — hard cap on one prompt |
| 3 | Rationale truncation | **400** chars |
| 4 | Next-step truncation | **300** chars |
| 5 | `minOverrideConfidence` | **50** |

### 12.5 LLM flags (shared by `triage`, `validate --triage`, `report --draft`)

| # | Flag | Default | Notes |
|---|---|---|---|
| 1 | `--llm-provider` | `ollama` | `ollama` (`/api/chat`) or `openai` (any compatible endpoint) |
| 2 | `--llm-endpoint` | *(empty -> `http://127.0.0.1:11434`)* | |
| 3 | `--llm-model` | *(empty)* | **Required** unless `--no-llm` |
| 4 | `--llm-timeout` | `120s` | Per batch request |
| 5 | `--no-llm` | `false` | Deterministic degradation |
| 6 | `--batch-size` | `12` | `triage` only; range 1-20 |

**API keys are read from the `SCOUTR_LLM_API_KEY` environment variable and nowhere
else** — never a flag, never persisted into a workspace artifact or `triage.json`.

```powershell
# Local, no key needed
ollama serve
ollama pull llama3.1
.\scoutr.exe triage --from .scoutr\runs\<run-dir> --llm-model llama3.1

# Remote OpenAI-compatible
$env:SCOUTR_LLM_API_KEY = "<key>"
.\scoutr.exe triage --from .scoutr\runs\<run-dir> `
  --llm-provider openai --llm-endpoint https://api.example.com/v1 --llm-model some-model

# No model at all
.\scoutr.exe triage --from .scoutr\runs\<run-dir> --no-llm
```

### 12.6 What the model never sees

The scope file, the resolved scope, and the raw target inventory. Only **redacted
finding evidence** is sent (`internal/triage.BuildEvidence`), so no model can influence a
scope decision or exfiltrate your target list. Credentials, tokens, cookies and the scope
file are never routed into a prompt.

---

## 13. Tier 2 — report drafting

```powershell
.\scoutr.exe report --from .scoutr\runs\<run-dir> --draft [--llm-model llama3.1 | --no-llm]
```

| Aspect | Behaviour |
|---|---|
| Precondition | `triage.json` must exist in the run dir |
| What gets drafted | `likely_true` and `needs_human` findings only |
| Where | `reports/drafts/` inside the run dir, plus `index.md` |
| Evidence | **Rendered by Go from the validated finding, never by the model.** A model cannot invent evidence |
| Guards | Every model string passes a **URL / CWE / CVSS** grounding check; anything ungrounded becomes the literal `NEEDS_HUMAN_INPUT` |
| Guard output | `guard_warnings` is recorded on the draft, so you can see what the model tried to claim |
| Title | The guarded title is the single value used for both the manifest and the H1 — the model gets no second, unchecked path into the file |
| CVSS | Seeded as `NEEDS_HUMAN_INPUT`, i.e. unknown until a human or a grounded model output sets it |
| CWE | Extracted deterministically from the finding |
| Isolation | `--draft` never overwrites the validated-findings report and never writes outside `reports/drafts/` |
| Status | Drafts are **never** submission-ready |

The drafting prompt's absolute rules: use only facts in `evidence`; do not invent URLs,
hosts, parameters, status codes, response bodies, screenshots, headers, technologies,
users or business impact; reproduction steps must derive from the evidence fields.

---

## 14. Tier 3 — human approval and submission

```powershell
.\scoutr.exe submit --require-approval --from .scoutr\runs\<run-dir>
.\scoutr.exe submit --require-approval --from .scoutr\runs\<run-dir> --finding <id>
.\scoutr.exe submit --list --from .scoutr\runs\<run-dir>
```

### 14.1 The mechanics

| # | Step | Detail |
|---|---|---|
| 1 | Flag check | Without `--require-approval`: `refusing to run: --require-approval is mandatory (there is no auto-approval path)` |
| 2 | Candidate filter | Gate status must be `Verified` **or** `NeedsManualReview`, with a triage verdict attached |
| 3 | Selection | 1 candidate -> auto-selected. Many -> you must pass `--finding`. None -> `nothing to approve: every candidate is already submission_ready` |
| 4 | Review printout | Title, severity, triage classification + rationale, and the **exact evidence bundle** from `validated_findings.json`, plus draft path and size |
| 5 | Keystroke | `Type APPROVE to mark this finding submission_ready (anything else cancels)` — unconditional, and there is **no** `--yes`, `--force` or `--non-interactive` |
| 6 | Write | Appends to `submission_ready.json` (`version`, `updated_at`, entries with finding ID, title, gate verdict, RFC3339 approval time) |
| 7 | Closing note | `No network request was made. scoutr does not submit to any platform; upload the draft yourself.` |

`--list` prints each candidate as
`[pending|submission_ready] <id> <title> gate=... triage=... SEVERITY`, then the queue size.

### 14.2 What `submission_ready` actually means

A local marker that **a human said yes, go submit it yourself.** A gate verdict of
`Verified` is explicitly *not* approval — a human still has to approve. Nothing marks a
finding `submission_ready` as a side effect of another command.

---

## 15. Workspace artifacts on disk

`scoutr run` creates `.scoutr\runs\<sanitized-target>-<YYYYMMDD-HHMMSS>\` (mode `0755`).

**Target sanitization:** strips `https://` / `http://`, replaces every character outside
`a-z A-Z 0-9 _ - .` with `_`, truncates at **50** chars. So `https://api.example.com/`
becomes `api.example.com`.

| # | File / dir | Written by | Contents |
|---|---|---|---|
| 1 | `inventory.json` | stages 1-3 | Enumerated and resolved asset inventory |
| 2 | `ports.json` | stage 2 | naabu ports, merged with nmap `Service`/`Product`/`Version` and HTTP fingerprints |
| 3 | `httpx.json` | stage 3 | Live HTTP endpoints |
| 4 | `crawl.json` | stage 4 | katana links/endpoints |
| 5 | `fuzz.json` | stage 5 | ffuf path candidates |
| 6 | `raw_findings.json` | stages 5-7 + `xss` | Pre-gate findings; `xss --from` **appends** to it |
| 7 | `validated_findings.json` | stage 8 | Gate verdicts + per-gate results. **The report source of truth** |
| 8 | `triage.json` | `triage` / `validate --triage` | Rankings only. Never feeds the report directly |
| 9 | `report.md` | stage 8 / `report --format md` | Markdown audit report |
| 10 | `report.html` | stage 8 / `report --format html` | Self-contained HTML, light/dark toggle |
| 11 | `reports/drafts/` | `report --draft` | One draft per eligible finding |
| 12 | `reports/drafts/index.md` | `report --draft` | Draft index |
| 13 | `submission_ready.json` | `submit` | Human-approved queue |

`.gitignore` covers `.scoutr/` and `reports/`, so recon output never gets committed.

```powershell
$run = (Get-ChildItem .scoutr\runs | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
Get-ChildItem $run -Recurse      # what this run produced
```

---

## 16. Worked end-to-end session

Steps 1-5 are exactly what was executed and verified on this host.

```powershell
# 1. Build
cd s:\bug-recon ; go build -o scoutr.exe ./cmd/scoutr

# 2. CI gate (Windows: raw go, no make needed)
go vet ./... ; go test ./... -count=1 ; gofmt -l .

# 3. Install the arsenal (nmap needs an elevated shell for winget)
.\scripts\install_tools.ps1 -WithNmap

# 4. Confirm availability
.\scoutr.exe arsenal --scope testdata\scope_valid.yaml

# 5. Plan only - sends nothing, creates no workspace
.\scoutr.exe run --scope scope.yaml --dry-run

# 6. LIVE pipeline against your authorized target (edit scope.yaml first)
.\scoutr.exe run --scope scope.yaml --external

# 7. Locate the run dir printed on stderr, then inspect
$run = (Get-ChildItem .scoutr\runs | Sort-Object LastWriteTime | Select-Object -Last 1).FullName

# 8. Tier 2 ranking - deterministic if you have no local model
.\scoutr.exe triage  --from $run --no-llm
.\scoutr.exe triage  --from $run --llm-model llama3.1

# 9. Drafts, then the human approval queue
.\scoutr.exe report  --from $run --draft --no-llm
.\scoutr.exe submit  --list --from $run
.\scoutr.exe submit  --require-approval --from $run   # type APPROVE

# 10. Final report artifacts
.\scoutr.exe report  --from $run --format md   -o report.md
.\scoutr.exe report  --from $run --format html -o report.html
```

**Expected shape of the results:** `validated_findings.json` will be sparse against a
placeholder or hardened target, because gate 3 needs real content signatures and gate 7
needs remediation plus references. Suppressed entries are the gate working, not a bug.

---

## 17. Troubleshooting

| # | Symptom | Cause | Fix |
|---|---|---|---|
| 1 | `make : The term 'make' is not recognized` | make isn't installed on Windows | Use the raw `go` commands (§3.2), or install make and run `fmt-check` from Git Bash |
| 2 | `--scope is required` | Missing persistent flag | Every command needs `--scope <file>` |
| 3 | `load scope: ...` parse error | Malformed YAML / wrong key names | Keys are exactly `in_scope` and `out_of_scope`; compare with `testdata\scope_valid.yaml` |
| 4 | `[INFO] <tool> not found on PATH, skipping...` | Tool missing | `.\scripts\install_tools.ps1`; re-check with `arsenal`. Never fatal |
| 5 | `scoutr scan` refuses to start | Honesty guard: no built-in checks in this build | Pass `--verify-posture`, or use `run` |
| 6 | `--llm-model is required for LLM triage/drafting` | Neither a model nor `--no-llm` was given | Add `--llm-model <name>` or `--no-llm` |
| 7 | `refusing to run: --require-approval is mandatory` | `submit` without the flag | Add `--require-approval` (by design, no bypass exists) |
| 8 | `nothing to approve: every candidate is already submission_ready` | Queue already drained | `submit --list` to see state |
| 9 | Red `NativeCommandError` and exit code 1 on a successful command | PowerShell treats stderr narration as an error | Ignore it; check the output/artifact. §6.3 explains why narration is on stderr |
| 10 | winget nmap fails with `0x800704c7 : The operation was canceled by the user` | UAC prompt dismissed / shell not elevated | Re-run from an elevated PowerShell. Optional tool — §4.4 |
| 11 | `ports.json` has empty `Service`/`Product`/`Version` | nmap missing (see #10) | Install nmap, or pass `--skip-nmap` explicitly |
| 12 | All triage verdicts are `needs_human` | You passed `--no-llm`, or the model returned free text | Expected. Deterministic degradation, not a failure |
| 13 | A finding you expected is `Suppressed` | Gate 1/2/3 rejected it | Read `gate_results[].reason` (§11.1) — it names the gate and the reason |
| 14 | No `.scoutr\runs\...` after `run --dry-run` | Dry-run returns before workspace creation | Artifacts require a live run (§8.3) |

---

## 18. Safety model and known limitations

### 18.1 Invariants you can rely on

| # | Invariant | Where it is enforced |
|---|---|---|
| 1 | Every HTTP request is scope-checked, redirects included | `ScopedTransport.RoundTrip` |
| 2 | External tool output is re-checked in scope | `FilterTargetsInScope` (pre) + `FilterDiscoveredItem` (post) |
| 3 | Deterministic code, not a model, decides verdicts | `internal/validate` |
| 4 | No path weakens the guard | no `--ignore-scope` / `--force` / `--unsafe` flag or env var exists |
| 5 | No platform API, no auto-submit | absent by design; Tier 3 is human-only |
| 6 | Pipeline order is not model-chosen | fixed Go enums in `internal/cli/run.go` |
| 7 | Model output is structured JSON or nothing | schema-pinned prompts + rejection -> `needs_human` |
| 8 | The LLM never sees scope or the target list | `internal/triage.BuildEvidence` sends redacted evidence only |

### 18.2 Limitations

1. **Built-in local checks are not implemented** — headers, cookies, exposure, domain
   takeover, CORS, TLS. `scan` is nuclei-posture-only and says so rather than reporting
   an empty clean scan.
2. **No Tier 3 automation** — no state-changing requests, no exploit payloads beyond
   standard probes, no submission.
3. **Version detection is best-effort.** `assetfinder`, `httpx` and `waybackurls` report
   `installed` instead of a version because their help output has no parsable token.
4. **`-race` has no local Windows equivalent here** — `CGO_ENABLED=0`. CI runs it on ubuntu.
5. **`make` targets assume a POSIX shell** — `fmt-check` uses `[ -n "$(gofmt -l .)" ]`.
6. **Version numbers move.** The tool versions in §4.3 are what `@latest` resolved to on
   the date of this document; yours will differ.
7. **External flags drift.** scoutr hardcodes each binary's flags (§9). A major upstream
   release can rename one — verify against upstream docs when a stage starts skipping.

---

## 19. References

### 19.1 Code index — where every claim in this guide comes from

| Section(s) | File | What it holds |
|---|---|---|
| §6.1, §7 | `internal\cli\root.go` | Root command, 16 persistent flags, config merge, banner |
| §7.1-§7.14 | `internal\cli\{enum,probe,urls,ports,crawl,fuzz,xss,scan,validate,triage,report,submit,run,arsenal}.go` | Per-command `Use`/`Short`/`Long`, `Example`, own flags |
| §12.5 | `internal\cli\llmflags.go` | The shared Tier 2 LLM flags |
| §8 | `internal\cli\run.go` | Stage order, `--skip-*` flags, dry-run branch |
| §4.1 | `internal\tools\tool.go` | `SupportedTools` registry: binary, tier, description, install hint, version args |
| §9 | `internal\tools\discovery.go` | subfinder/amass/assetfinder/dnsx/httpx/gau/katana/nuclei command lines, `BuildScopeRegex` |
| §9, §9.1 | `internal\tools\stages.go` | naabu/nmap/ffuf/dalfox command lines, budget constants, rate fallbacks |
| §9.1 | `internal\tools\wordlist_paths.txt` | 49 curated paths for ffuf |
| §9.1 | `internal\recon\subdomains\wordlist.txt` | 113 DNS brute-force entries |
| §11 | `internal\validate\validator.go` | Verdict constants, `GateResult`, all 7 gates |
| §11 | `internal\validate\signatures.go`, `remediation.go` | Content signatures, `LookupRemediation` |
| §10 | `internal\findings\finding.go` | `Finding`, severity/confidence enums, `Key()`, `Validate()` |
| §12 | `internal\triage\triage.go` | Classifications, batch/truncation/confidence constants |
| §12.3 | `internal\triage\rules.go` | The 3 hard rules + `HardRuleDocumentation()` |
| §12.5, §12.6 | `internal\triage\client.go`, `prompt.go` | Providers, `APIKeyEnv`, schema-pinned prompts |
| §13 | `internal\draft\draft.go` | Drafting contract, `NEEDS_HUMAN_INPUT`, guards |
| §14 | `internal\cli\submit.go` | Approval filter, `APPROVE` prompt, queue schema |
| §15 | `internal\workspace\workspace.go` | Artifact filenames, run-dir layout, `SanitizeTarget` |
| §5 | `internal\scope\scope.go`, `internal\httpx\client.go` | Scope model, transport guard |
| §6.2 | `internal\config\config.go` | `FileConfig` keys, merge and validation |
| §3.3, §3.4 | `Makefile`, `.github\workflows\ci.yml` | Build targets, CI gate |
| §4.2 | `scripts\install_tools.ps1`, `scripts\install_tools.sh` | Arsenal installers |
| §1 | `AGENTS.md`, `README.md`, `docs\PROGRESS.md` | Project constraints, quick start, milestone history |

### 19.2 Upstream tool documentation

| Tool | Repository / docs |
|---|---|
| subfinder, dnsx, httpx, katana, nuclei, naabu | `github.com/projectdiscovery/<name>` |
| amass | `github.com/owasp-amass/amass` |
| assetfinder, waybackurls | `github.com/tomnomnom/<name>` |
| gau | `github.com/lc/gau` |
| ffuf | `github.com/ffuf/ffuf` |
| dalfox | `github.com/hahwul/dalfox` |
| nmap | `nmap.org/book/man.html` |
| Ollama | `ollama.com` — `/api/chat` endpoint |

### 19.3 Standards referenced by the gate and reports

| Standard | Where it appears |
|---|---|
| CWE | Gate 7 references, `first_cwe_occurrence` rule, draft `cwe` field guard |
| CVSS 3.1 | Draft `cvss_vector` field, guarded; `NEEDS_HUMAN_INPUT` when ungrounded |
| OWASP | Reference URLs on findings; `exposure` / `misconfig` nuclei tags |
| Certificate Transparency | crt.sh in stage 1 |

---

## 20. Revision history

| Rev | Date | Change | Verified by |
|---|---|---|---|
| A | 2026-11-02 | Initial guide: setup, all 14 commands, 13-tool arsenal with exact command lines, the 7-check gate, Tier 2/3 flows, workspace layout, troubleshooting, code index | Built and run on Windows 11 26H2 / go1.27.0 at commit `5492ce9`; `go vet` clean, all test packages pass, `arsenal` re-run post-install, `run --dry-run` output captured |

*Document ends.*
