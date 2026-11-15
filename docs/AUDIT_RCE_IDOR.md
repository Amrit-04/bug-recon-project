# Codebase Audit & Architecture Specification: Scoutr RCE & IDOR Platform Upgrade

**Document ID:** AUDIT-RCE-IDOR-001  
**Target:** Scoutr Reconnaissance & Validation Engine (`github.com/scoutr/scoutr`)  
**Status:** Approved Architectural Blueprint (Phase 1 Complete)  

---

## 1. Executive Summary

This audit assesses the current state of Scoutr against the requirements for upgrading it into a scope-safe Remote Code Execution (RCE) and Insecure Direct Object Reference (IDOR) research platform.

Scoutr currently operates with a **deterministic backbone** and a **narrow, non-authoritative LLM layer**. It enforces target boundaries through a custom transport-layer scope guard (`ScopedTransport`), feeds findings through an authoritative 7-Check Readiness Gate (`internal/validate`), persists artifacts in timestamped workspace directories (`internal/workspace`), and separates autonomous actions (Tiers 0/1) from advisory LLM ranking (Tier 2) and human approval (Tier 3).

The RCE and IDOR research platform will build upon this architecture without breaking existing workflows, without weakening the transport-layer scope guard, and without introducing autonomous destructive exploit behavior.

---

## 2. Artifact & Stage Mapping

### 2.1 Existing Pipeline Stages & Artifacts

| Stage | Subsystem | Executed By | Artifact File | Format | Description |
|---|---|---|---|---|---|
| **enum** | `internal/recon/subdomains`, `internal/tools` | Native HTTP (crt.sh) & External (`subfinder`, `amass`, `assetfinder`, `dnsx`) | `inventory.json` | JSON / JSONL | Unique list of in-scope hostnames. |
| **ports** | `internal/tools` | External (`naabu`, `nmap -sV`) | `ports.json` | JSON array | Open ports, services, versions. |
| **probe** | `internal/tools`, `internal/recon/probe` | External (`httpx`) / Native (`probe.Host`) | `httpx.json` | JSON array | Live HTTP status, titles, webservers, tech tags. |
| **crawl** | `internal/tools` | External (`katana`) | `crawl.json` | JSON array | Crawled URL paths and endpoints. |
| **fuzz** | `internal/tools` | External (`ffuf`) | `fuzz.json` | JSON array | Discovered directory and file paths. |
| **xss** | `internal/tools` | External (`dalfox`) | In-memory raw finding | `findings.Finding` | Reflected XSS candidates. |
| **nuclei** | `internal/tools` | External (`nuclei`) | In-memory raw finding | `findings.Finding` | Read-only posture check findings (strictly non-exploit tags). |
| **validate** | `internal/validate` | Native Go | `raw_findings.json`, `validated_findings.json`, `report.md`, `report.html` | JSON / Markdown / HTML | Authoritative 7-Check Readiness Gate verdicts (`Verified`, `NeedsManualReview`, `Suppressed`). |

### 2.2 Existing Post-Pipeline Stages & Artifacts

| Stage | Subsystem | Executed By | Artifact File | Format | Description |
|---|---|---|---|---|---|
| **urls** | `internal/cli/urls.go` | External (`waybackurls`, `gau`) | stdout / optional file | Plaintext URLs | Historical archive URLs. |
| **triage** | `internal/triage` | Native Go -> Local LLM | `triage.json` | JSON | Tier-2 ranking (`likely_true`, `likely_false`, `needs_human`) with hard-rule veto layer. |
| **draft** | `internal/draft` | Native Go -> Local LLM | `reports/drafts/*.md`, `index.md` | Markdown | Markdown draft reports with Go-generated evidence blocks. |
| **submit** | `internal/cli/submit.go` | Native Go | `submission_ready.json` | JSON | Interactive approval queue requiring typed `APPROVE`. |

---

## 3. Network Transport & Egress Audit

### 3.1 Native Go HTTP Requests (Scope Enforced)
- **`internal/httpx.Client` & `ScopedTransport`:**
  - Enforces `scope.Scope` at `RoundTrip` time for **every outbound HTTP request**.
  - Intercepts all redirects via `http.Client.CheckRedirect`; redirects to out-of-scope hosts are aborted immediately.
  - Implements global and per-host token-bucket rate limiting via `golang.org/x/time/rate`.
  - Wraps response bodies in `io.LimitReader` to enforce `maxBodySize`.
  - Injects consistent User-Agent and headers.
  - **Audit Finding:** All new native requests (endpoint intelligence probes, API spec fetching, dual-account IDOR differential requests, safe RCE surface probes) **must** utilize `httpx.Client` with `ScopedTransport`.

### 3.2 External CLI Tool Executions (Boundary Enforced)
- **`internal/tools.SafeToolExecution` & `CommandRunner`:**
  - Binaries (`subfinder`, `amass`, `assetfinder`, `dnsx`, `naabu`, `nmap`, `httpx`, `katana`, `ffuf`, `dalfox`, `nuclei`, `waybackurls`, `gau`) run outside Go's HTTP transport.
  - Pre-execution guard: `FilterTargetsInScope` filters all inputs before CLI execution.
  - Post-execution guard: `FilterDiscoveredItem` discards any discovered items outside scope.
  - **Audit Finding:** While target arguments are strictly filtered, external tools make their own network socket connections. For complete assurance, external active tools must be constrained with bounded concurrency (`-c`), enforced rate limits (`-rl`), and prohibited exploit flags (`-etags fuzz,intrusive,dos,exploit,rce,sqli,xss,lfi,ssrf`).

---

## 4. Integration Points for RCE & IDOR

### 4.1 Phase 2: Central Endpoint Intelligence (`internal/endpoints`)
- **Location:** New package `internal/endpoints` integrating into `internal/pipeline` and `internal/workspace`.
- **Inputs:**
  - Endpoints from `crawl.json` (katana).
  - Endpoints from `fuzz.json` (ffuf).
  - Live endpoints from `httpx.json`.
  - Historical archive URLs (`waybackurls`, `gau`) integrated into the full pipeline.
  - Public API specifications (`/openapi.json`, `/swagger.json`, etc.) probed via `httpx.Client`.
  - JavaScript endpoint extraction (scraping script paths from crawl results).
- **Core Abstractions:**
  - `Endpoint`: URL, normalized route, HTTP methods, query params, JSON body fields, content types, authentication requirements, tech fingerprints, provenance, classifications, response metadata.
  - `Inventory`: Central deduplicated, thread-safe endpoint registry.
  - `Classifier`: Deterministic rules categorizing endpoints (file upload, document conversion, template rendering, user data, admin, export, etc.).
- **Artifact:** `endpoints.json` stored in workspace.

### 4.2 Phase 3: IDOR Research Engine (`internal/idor`)
- **Location:** New package `internal/idor` with CLI command `scoutr idor` and pipeline hooks.
- **Core Abstractions:**
  - `Profile`: Holds researcher credentials for Account A (Owner) and Account B (Auditor) (session cookies, Bearer tokens, custom headers).
  - `HARImporter`: Parses researcher HAR captures, sanitizing credentials and mapping object identifiers to owners.
  - `CandidateExtractor`: Extracts object identifiers from routes (`/api/doc/{id}`), query params (`?id=`, `?account=`), and JSON bodies.
  - `DifferentialAuditor`: Uses `httpx.Client` to perform three read-only requests:
    1. Account A (baseline owner access - verify 200 OK).
    2. Account B (cross-account test - check if unauthorized access permitted).
    3. Unauthenticated (check if resource is public/unprotected).
  - `Canonicalizer`: Strips nonces, timestamps, CSRF tokens, and compares response bodies to calculate similarity.
  - `CacheDetector`: Verifies `Cache-Control` / CDN headers to eliminate caching false positives.
- **Safety Enforcement:**
  - Read-only `GET` operations only.
  - No arbitrary identifier enumeration.
  - Mutating operations (`POST`, `PUT`, `DELETE`) require explicit interactive human approval flag (`--allow-mutating`).
  - Auth secrets are redacted and **never passed to LLM**.
- **Artifact:** `idor_candidates.json` stored in workspace; generates raw findings for validated issues.

### 4.3 Phase 4: RCE Research Engine (`internal/rce`)
- **Location:** New package `internal/rce` with CLI command `scoutr rce` and pipeline hooks.
- **Core Abstractions:**
  - `SurfaceClassifier`: Prioritizes high-risk attack surfaces identified in `endpoints.json`:
    - File processing & uploads.
    - Document conversion (PDF/Word/HTML).
    - Template rendering (Jinja, Freemarker, Blade, Thymeleaf).
    - Archive extraction.
    - Import / export (XML, CSV, JSON).
    - Image processing (ImageMagick, GraphicsMagick).
    - Webhooks & background job triggers.
    - Build & workflow systems.
  - `AdvisoryCorrelator`: Local in-memory catalog of high-impact public advisories (CVEs) correlated against technology fingerprints (`httpx.json`) and specific component versions.
  - `SafeProber`: Strictly read-only, non-destructive signature inspection with explicit allowlists. Zero arbitrary command execution, zero reverse shells, zero file writes.
  - `StatusTracker`: Categorizes findings strictly into `candidate` -> `corroborated` -> `confirmed` (with confirmed requiring human review).
- **Artifact:** `rce_candidates.json` stored in workspace; generates raw findings for corroborated issues.

### 4.4 Phase 5: Finding Schema & Deterministic Gate Extension (`internal/findings`, `internal/validate`)
- **Finding Schema Extension:**
  - Add structured, vulnerability-specific evidence fields for IDOR and RCE:
    - IDOR: Principal A label, Principal B label, target object, owner status, cross-user status, public status, similarity percentage, redacted request/response snippets.
    - RCE: Suspected functionality, affected technology, advisory ID, discovery evidence, validation state, human verification notes.
- **7-Check Gate Extensions:**
  - Gate 1 (Scope): Absolute enforcement on target host.
  - Gate 2 (Soft-404 / Public Resource): Discard IDOR if unauthenticated request returns identical data.
  - Gate 3 (Signature / Evidence): Verify complete redacted evidence with both principal perspectives for IDOR, and documented technology proof for RCE.
  - Gate 4 (Impact): Proper severity scoring (Critical for corroborated RCE, High/Medium for verified IDOR).
  - Gate 5 (Redaction): Strict verification that no raw tokens or cookies exist in evidence strings.

---

## 5. Implementation Roadmap by Milestones

1. **Milestone 1:** Codebase Audit & Architectural Plan (`docs/AUDIT_RCE_IDOR.md`). *(This Document)*
2. **Milestone 2:** Phase 2 — Shared Endpoint Intelligence (`internal/endpoints`, normalization, extraction, classification, tests).
3. **Milestone 3:** Phase 3 — IDOR Research Engine (`internal/idor`, dual-account differential auditor, HAR importer, tests).
4. **Milestone 4:** Phase 4 — RCE Research Engine (`internal/rce`, surface classifier, local advisory correlator, safe prober, tests).
5. **Milestone 5:** Phase 5 & 6 — Validation Gate & Schema Extension (`internal/findings`, `internal/validate`, report templates, audit logging).
6. **Milestone 6:** Phase 7 — Comprehensive Local Mock Scenarios & End-to-End Verification (`go test ./... -count=1`, documentation updates).
