# Scoutr Phase 4: Advanced RCE Discovery and Research Engine
## Architectural Specification, Engineering Report, and Verification Audit

**Status:** Completed & Validated  
**Version:** Scoutr v1.0 (Phase 4 Milestone)  
**Date:** November 2026  
**Repository:** [https://github.com/Amrit-04/bug-recon-project](https://github.com/Amrit-04/bug-recon-project)  
**Test Suite:** 19/19 Go packages passing, 17/17 Vitest frontend tests passing, 7/7 Playwright E2E workflows passing  

---

## 1. Executive Summary

Phase 4 transforms Scoutr into an application-aware **Remote Code Execution (RCE) research and validation engine**. Instead of acting as a generic vulnerability scanner or wrapping third-party tools, Scoutr operates as a specialized, hypothesis-driven research platform designed for authorized security researchers and bug bounty professionals.

The engine analyzes endpoint inventory, parameter semantics, and technology fingerprints to discover potential server-side execution attack surfaces, reconstruct multi-step processing chains, correlate detected dependencies against known public vulnerability advisories (CVE/GHSA), prioritize candidates using a transparent deterministic scoring formula, and conduct safe, non-destructive validation under strict scope control.

### Core Architectural Principles

1. **Deterministic Authority**: All candidate classification, multi-step chain analysis, score breakdowns, advisory reachability tiers, and validation decisions are governed by deterministic Go logic. AI/LLM components remain strictly advisory.
2. **Absolute Scope Guard**: Every active network probe initiated during RCE validation is routed through Scoutr's native `httpx.ScopedTransport`. Scope checks are enforced at the transport layer; out-of-scope requests and redirects are terminated before network transmission.
3. **Graduated 3-Profile Validation**:
   - **Profile 1 (Passive Research)**: Zero target network traffic; evaluates endpoint metadata, parameter structures, and public advisories.
   - **Profile 2 (Safe Active Probing)**: Controlled, non-destructive mathematical marker arithmetic (`${7*7}` -> `49`, negative control `${7*8}` -> `56`) with strict reflection detection and negative control verification. Never executes shell commands, system utilities, or network exfiltration.
   - **Profile 3 (Manual Verification Plan)**: Prepares safe, reproducible `curl` commands and step-by-step audit plans for human researcher review.
4. **Dual Interface**: Full feature parity between the Go CLI (`scoutr rce`) and the React web dashboard (`RCE Research Center`).

---

## 2. Package Architecture (`internal/rce`)

The RCE research engine is implemented in the `internal/rce` package, modularized into cohesive, single-responsibility files:

```
internal/rce/
├── types.go          # Core domain models, enums, JSON tags, and progression tiers
├── classifier.go     # Heuristic classification for 6 execution sink categories
├── chains.go         # Multi-step processing chain correlation (e.g. upload -> conversion -> worker)
├── advisory.go       # Curated advisory registry, semver range evaluator, and 6-tier progression model
├── prioritize.go     # Deterministic scoring formula and transparent explanation generator
├── validator.go      # Graduated 3-profile validation engine with non-destructive markers
├── report.go         # Comprehensive Markdown report generator
└── rce_test.go       # Exhaustive unit test suite covering all subsystems
```

### 2.1 Domain Models (`types.go`)

The core entity is `RCECandidate`:

```go
type RCECandidate struct {
    ID                 string              `json:"id"`
    Target             string              `json:"target"`
    Origin             string              `json:"origin"`
    Route              string              `json:"route"`
    HTTPMethod         string              `json:"http_method"`
    Category           RCECategory         `json:"category"`
    FeatureType        string              `json:"feature_type"`
    Hypothesis         string              `json:"hypothesis"`
    SuspectedSink      string              `json:"suspected_sink"`
    RelevantParams     []string            `json:"relevant_params,omitempty"`
    RelevantBodyFields []string            `json:"relevant_body_fields,omitempty"`
    RelevantTech       []string            `json:"relevant_tech,omitempty"`
    DiscoverySource    string              `json:"discovery_source"`
    EvidenceSignals    []string            `json:"evidence_signals"`
    Confidence         RCEConfidence       `json:"confidence"`
    PriorityScore      int                 `json:"priority_score"`
    ScoreBreakdown     ScoreBreakdown      `json:"score_breakdown"`
    AssociatedChains   []ProcessingChain   `json:"associated_chains,omitempty"`
    MatchingAdvisories []AdvisoryMatch     `json:"matching_advisories,omitempty"`
    ValidationAttempts []ValidationAttempt `json:"validation_attempts,omitempty"`
    LastAttempt        *ValidationAttempt  `json:"last_attempt,omitempty"`
    ValidationStatus   ValidationStatus    `json:"validation_status"`
    ResearcherNotes    string              `json:"researcher_notes,omitempty"`
    DiscoveredAt       time.Time           `json:"discovered_at"`
    UpdatedAt          time.Time           `json:"updated_at"`
}
```

---

## 3. Execution Sink Taxonomy & Detection Rules

The classification engine (`classifier.go`) inspects endpoint paths, query parameters, body parameters, headers, and technology fingerprints to identify 6 high-risk execution sink categories:

### 3.1 Category 1: Command Injection (`command_injection`)
- **Heuristic Indicators**: Routes or parameters indicating operating system utilities: `ping`, `traceroute`, `nslookup`, `whois`, `dig`, `curl`, `wget`, `sh`, `bash`, `cmd`, `exec`, `spawn`, `system`, `shell`, `run`, `backup`, `cli`.
- **Target Functional Areas**: Network diagnostic panels, remote maintenance tools, backup utilities, CLI execution endpoints.
- **Base Risk**: 35 points (highest base sink severity).

### 3.2 Category 2: Server-Side Template Injection (`ssti`)
- **Heuristic Indicators**: Routes containing `/export/pdf`, `/render`, `/preview`, `/template`, `/generate/report`, `/invoice`, `/email/preview`, `/badge/render`. Parameters such as `template`, `tpl`, `layout`, `view`, `format`, `theme`, `engine`.
- **Technologies Correlated**: Jinja2, Twig, FreeMarker, Velocity, Thymeleaf, ERB, Smarty, Pebble.
- **Base Risk**: 30 points.

### 3.3 Category 3: Unsafe Deserialization (`unsafe_deserialization`)
- **Heuristic Indicators**: Routes accepting serialized objects (`/unserialize`, `/deserialize`, `/rpc`, `/remoting`, `/job/submit`, `/queue/push`). Content types like `application/x-java-serialized-object`, `application/x-python-serialize`. Magic byte prefixes (`rO0` for Java, `O:` or `a:` for PHP, `cos\n` for Python pickle).
- **Technologies Correlated**: Java RMI/Spring, Python pickle/PyYAML, PHP serialize, .NET BinaryFormatter.
- **Base Risk**: 30 points.

### 3.4 Category 4: File Processing & Parser Sinks (`file_processing`)
- **Heuristic Indicators**: File uploads, converters, or document processors (`/convert`, `/transform`, `/resize`, `/thumbnail`, `/transcode`, `/parse/xml`, `/parse/doc`). Parameters like `file`, `doc`, `pdf`, `image`, `upload`, `document`, `attachment`.
- **Technologies Correlated**: ImageMagick, Ghostscript, FFmpeg, LibreOffice, Pandoc, Apache Tika, Batik SVG parser.
- **Base Risk**: 25 points.

### 3.5 Category 5: Expression Language Injection (`expression_language`)
- **Heuristic Indicators**: Endpoints in Java Spring, Struts, or JSF ecosystems accepting dynamic expressions, navigation targets, or action evaluations (`/action`, `/do`, `/invoke`, `/eval`, `/expr`).
- **Technologies Correlated**: OGNL, Spring SpEL, MVEL, Unified EL (`${...}`, `%{...}`, `#{...}`).
- **Base Risk**: 25 points.

### 3.6 Category 6: Dependency / Framework RCE (`dependency_rce` & `background_job_rce`)
- **Heuristic Indicators**: Discovered framework components with public advisory matches (e.g. Spring4Shell, Log4Shell, Laravel Ignition), and asynchronous job queue managers (`/admin/queues`, `/sidekiq`, `/celery`, `/bullmq`, `/resque`).
- **Base Risk**: 20-25 points.

---

## 4. Multi-Step Processing Chains (`chains.go`)

Real-world RCE vulnerabilities rarely exist as a single isolated GET or POST request. They often involve a multi-step pipeline where input is submitted at one stage and processed asynchronously by a vulnerable backend sink at a later stage.

Scoutr models this via `ProcessingChain`:
1. **Upload Source (`upload_source`)**: An unauthenticated or authenticated endpoint accepting user-controlled documents, archives, or templates.
2. **Converter / Parser Sink (`converter_sink`)**: A conversion or preview endpoint (e.g. `/api/v1/export/pdf`, `/api/v1/convert`) that processes the uploaded artifact.
3. **Worker Trigger (`worker_trigger`)**: An asynchronous task queue or background worker that executes document processing or external system commands.

Candidates linked to a verified multi-step chain receive an automatic **+10 to +15 point priority boost** (`ChainModifier`), highlighting chained attack paths to the researcher.

---

## 5. Curated Advisory Registry & 6-Tier Progression Model (`advisory.go`)

### 5.1 Curated Advisory Intelligence
Scoutr includes a built-in, curated registry of high-impact server-side RCE advisories:
- **CVE-2022-22965 (Spring4Shell)**: Spring Framework RCE via DataBinder parameter binding (`>= 5.3.0, < 5.3.18`).
- **CVE-2021-44228 (Log4Shell)**: Apache Log4j2 JNDI injection (`>= 2.0.0, < 2.15.0`).
- **CVE-2017-5638 (Apache Struts2)**: OGNL injection in Jakarta Multipart parser (`>= 2.3.5, < 2.3.32`).
- **CVE-2022-26134 (Atlassian Confluence)**: OGNL injection via HTTP request URI (`>= 1.3.0, < 7.18.0.1`).
- **CVE-2018-16509 (Ghostscript)**: Pipe command execution bypass in PostScript handling (`< 9.24.0`).
- **CVE-2016-3714 (ImageTragick)**: ImageMagick shell escape via MVG/MSL delegate handling (`< 6.9.3.10`).
- **CVE-2021-3129 (Laravel Ignition)**: Facade Ignition deserialization RCE (`<= 2.5.1`).
- **CVE-2023-46604 (Apache ActiveMQ)**: OpenWire protocol arbitrary class instantiation (`>= 5.0.0, < 5.18.3`).
- **CVE-2023-27350 (PaperCut MF)**: Authentication bypass to remote code execution (`>= 8.0.0, < 22.0.9`).
- **CVE-2023-22527 (Confluence SSTI)**: Template injection in Confluence Data Center (`>= 8.0.0, < 8.5.4`).

### 5.2 Six-Stage Reachability Progression Model

A software version match alone **must never** be reported as a confirmed vulnerability. Scoutr enforces a strict 6-stage advisory progression model:

| Stage Tier | Designation | Criteria |
|---|---|---|
| Tier 1 | `tech_detected` | The technology or vendor ecosystem (e.g. Spring, Laravel) is detected in headers or responses. |
| Tier 2 | `version_identified` | A concrete version number is extracted from fingerprints, banners, or asset metadata. |
| Tier 3 | `version_affected` | The extracted version satisfies the semver vulnerable range criteria. |
| Tier 4 | `component_corroborated` | A required component or prerequisite configuration (e.g. JDK 9+, WAR packaging, OpenWire port) is identified. |
| Tier 5 | `component_reachable` | A live endpoint in scope accepts user input and directly exposes the vulnerable feature or parameter. |
| Tier 6 | `independently_validated` | A safe active probe or non-destructive check has independently verified execution sink behavior. |

Only candidates reaching `component_reachable` or higher receive substantial priority boosts (+18 to +25 points).

---

## 6. Deterministic Prioritization Formula (`prioritize.go`)

Prioritization is completely transparent, deterministic, and mathematical. Every candidate produces a `ScoreBreakdown` with explicit weights:

$$\text{Total Score} = \min(100, \text{BaseRisk} + \text{InputExposure} + \text{AuthModifier} + \text{TechCVEModifier} + \text{ChainModifier})$$

### Score Components:
1. **Base Risk (10 - 35 points)**:
   - Command Injection: 35
   - SSTI: 30
   - Unsafe Deserialization: 30
   - Expression Language: 25
   - File Processing / Document Converter: 25
   - Dependency / Job Queue RCE: 20
2. **Input Exposure (5 - 25 points)**:
   - POST / PUT / PATCH body: +15
   - Multipart file upload: +15
   - Query string parameters: +10
   - Multiple parameters exposed: +5
3. **Authentication Barrier (0 - 20 points)**:
   - Anonymous / Unauthenticated: +20 (publicly accessible attack surface)
   - Authenticated Member: +10
   - Administrative Role: +0
4. **Tech / CVE Modifier (0 - 25 points)**:
   - Reachable CVE (`component_reachable`): +25
   - Affected CVE (`version_affected`): +15
   - Corroborated Tech Fingerprint: +10
5. **Chain Modifier (0 - 15 points)**:
   - Part of confirmed multi-step pipeline (Upload -> Convert -> Worker): +15

### Researcher Transparency:
Each calculation populates `ScoreBreakdown.Explanations` with clear human-readable strings explaining exactly why each point was awarded (e.g. `"+30 base risk: High-severity Template Injection sink"`, `"+20 auth modifier: Unauthenticated public attack surface"`).

---

## 7. Graduated 3-Profile Validation Engine (`validator.go`)

Scoutr strictly separates research into three authorized validation profiles:

```
+----------------------------------------------------------------------------------+
|                            SCOUTR VALIDATION PROFILES                            |
+----------------------------------------------------------------------------------+
| [Profile 1: Passive]      | Zero network traffic; analyzes metadata & advisories |
| [Profile 2: Safe Active]  | Benign math markers (${7*7}->49, ${7*8}->56), checks |
| [Profile 3: Manual Plan]  | Generates reproducible curl command for researcher   |
+----------------------------------------------------------------------------------+
```

### 7.1 Safe Active Marker Design (Profile 2)
To validate execution sinks without destructive actions or shellcode:
1. **Positive Mathematical Probe**:
   - For SSTI / Template Engines: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`.
   - Expected Marker: `49`.
2. **Negative Control Probe**:
   - Sends a secondary probe with distinct operands: `${7*8}` or `{{7*8}}`.
   - Expected Marker: `56`.
3. **Strict Reflection Exclusion**:
   - The engine checks if the raw payload (`${7*7}`) appears verbatim in the response body.
   - If the raw payload is echoed verbatim, the check **fails closed** (`needs_manual_review`) to prevent misclassifying reflected XSS or echoed inputs as RCE.
   - Execution is confirmed **only** if the calculated arithmetic result (`49`) is present, the negative control result (`56`) is present, and reflection is excluded.
4. **Transport-Layer Scope Check**:
   - Every request uses `httpx.New(globalConfig)` which wraps `httpx.ScopedTransport`.
   - If any URL or redirect resolves out-of-scope, the Go runtime halts the connection immediately.

---

## 8. CLI & REST API Interfaces

### 8.1 CLI Subsystem (`internal/cli/rce.go`)
- `scoutr rce discover [--min-priority N] [--json]`: Scans endpoint inventory, extracts candidates, correlates advisories, and stores `rce_candidates.json`.
- `scoutr rce list [--category C] [--status S] [--min-priority N]`: Displays prioritized candidates in an interactive CLI table with confidence and sink details.
- `scoutr rce validate --id <cid> [--profile passive|safe_active|manual] [--auth <principal>]`: Runs the 3-profile validation gate against a candidate.
- `scoutr rce report [--output rce_report.md]`: Compiles and exports the complete RCE research report.

### 8.2 REST API Routes (`internal/server/rce_api.go`)
- `GET /api/runs/{id}/rce/overview`: Returns KPI metrics, execution sink breakdown, and advisory match counts.
- `GET /api/runs/{id}/rce/candidates`: Returns filterable candidates (`category`, `status`, `min_priority`, `tech`, `search`).
- `GET /api/runs/{id}/rce/candidates/{cid}`: Returns single candidate details with score breakdown and validation history.
- `PUT /api/runs/{id}/rce/candidates/{cid}`: Updates researcher notes and manual validation status.
- `POST /api/runs/{id}/rce/discover`: Launches asynchronous background discovery job. Emits SSE `rce_candidate_discovered`.
- `GET /api/runs/{id}/rce/advisories`: Returns curated advisory database and matching endpoint references.
- `POST /api/runs/{id}/rce/validate`: Executes profile validation (Passive, Safe Active, or Manual). Emits SSE `rce_validation_result`.
- `GET /api/runs/{id}/rce/report`: Generates and streams full Markdown report.

---

## 9. React Frontend: RCE Research Center (`web/src/App.jsx`)

The browser interface provides a dedicated **RCE Research Center** tab featuring 5 sub-tabs:

1. **1. Overview & Sinks**:
   - Real-time KPI summary cards (Total Attack Surfaces, Candidates in Queue, Reachable Advisories, Validated Sinks).
   - Execution Sink Classification Grid (Command Injection, SSTI, Deserialization, File Processing, Expression Language, Dependency RCE) displaying sink descriptions, detection heuristics, and live candidate count badges.
2. **2. Attack Surface Explorer**:
   - Full-text search and category filter pills.
   - Comprehensive table listing HTTP Method, Route Template, Execution Sink Category, Observed Parameters, Confidence, and Priority Score.
   - Interactive Candidate Detail Drawer inspecting parameter exposures, technology context, and hypotheses.
3. **3. Candidate Prioritization Queue**:
   - Cards sorted by priority score (0-100) with color-coded risk indicators.
   - **Deterministic Score Breakdown Matrix**: Shows exact points awarded for Base Sink Risk, Input Exposure, Auth Barrier, and Tech/CVE Modifiers.
   - **Score Rationale List**: Bulleted human-readable explanations.
   - **Multi-Step Processing Chain Steps**: Visual step progression diagram when candidates participate in chained workflows.
   - **Researcher Notes & Manual Gate Editor**: Inline notes textarea and status selector (`candidate`, `needs_review`, `verified`, `suppressed`) with atomic persistence.
4. **4. Advisory Intelligence (CVEs)**:
   - Public vulnerability advisory registry display.
   - Semver vulnerable range badges, CVSS scores, severity tags, and prerequisite descriptions.
   - Reachability Progression Tier badges (`Component Reachable`, `Component Corroborated`, `Tech Detected`).
   - Mapped endpoints and reachability rationale.
5. **5. Validation Center**:
   - Summary statistics of validated vs reviewed candidates.
   - Audit table with candidate routes, validation profile, and gate verdicts.
   - **Launch 3-Profile Validation Gate Modal**: Profile selector (Passive, Safe Active, Manual), authentication profile selector, scope enforcement reminder, and live execution button.
   - **RCE Evidence Bundle & Verification Audit Modal**: Displays target route, canonical URL, ScopedTransport enforcement status, marker sent/expected, reflection check pass/fail, negative control verification pass/fail, and reproducible `curl` command with one-click clipboard copying.

---

## 10. Verification & Quality Assurance Audit

All verification gates were executed and passed across both backend and frontend layers:

```
================================================================================
                    SCOUTR PHASE 4 VERIFICATION AUDIT
================================================================================

1. Go Unit Tests (19 of 19 packages passing):
   ok   github.com/scoutr/scoutr/internal/auth         (cached)
   ok   github.com/scoutr/scoutr/internal/cli          1.728s
   ok   github.com/scoutr/scoutr/internal/config       (cached)
   ok   github.com/scoutr/scoutr/internal/draft        (cached)
   ok   github.com/scoutr/scoutr/internal/endpoints    (cached)
   ok   github.com/scoutr/scoutr/internal/findings     (cached)
   ok   github.com/scoutr/scoutr/internal/httpx        (cached)
   ok   github.com/scoutr/scoutr/internal/idor         (cached)
   ok   github.com/scoutr/scoutr/internal/pipeline     (cached)
   ok   github.com/scoutr/scoutr/internal/rce          2.933s
   ok   github.com/scoutr/scoutr/internal/recon/probe  (cached)
   ok   github.com/scoutr/scoutr/internal/recon/subdomains (cached)
   ok   github.com/scoutr/scoutr/internal/report       (cached)
   ok   github.com/scoutr/scoutr/internal/scope        (cached)
   ok   github.com/scoutr/scoutr/internal/server       30.182s
   ok   github.com/scoutr/scoutr/internal/tools        (cached)
   ok   github.com/scoutr/scoutr/internal/triage       (cached)
   ok   github.com/scoutr/scoutr/internal/validate     (cached)
   ok   github.com/scoutr/scoutr/internal/workspace    (cached)

2. Frontend Unit Tests (Vitest):
   ✓ src/App.test.jsx (17 tests) - 100% PASSING

3. Playwright Browser E2E Integration Suite:
   ✓ Workflow A: Run discovery -> Inspect endpoint inventory in UI
   ✓ Workflow B: Configure User A & User B -> Verify sessions -> Check status in UI
   ✓ Workflow C: Import HAR capture -> Candidate extraction -> Review candidates in UI
   ✓ Workflow D: Execute differential testing -> Inspect comparison matrix & evidence bundle
   ✓ Workflow E: External scanner execution with scope verification
   ✓ Workflow F: SSE live progress streaming & cancellation
   ✓ Workflow G: RCE Research Center -> Attack Surface Discovery -> Advisory Reachability & Validation
   7 passed (9.0s) - 100% PASSING

4. Static Analysis:
   - `go vet ./...`: 0 warnings, clean.
   - `gofmt -l .`: 0 unformatted files, clean.
   - Production Vite Build: `dist/` bundle compiled in ~3.9s.
================================================================================
```

---

## 11. Security Guardrails & Limitations

1. **Non-Destructive Boundary**: Scoutr strictly refuses to generate or transmit destructive payloads (e.g. `rm -rf`, file modification, reverse shells, memory corruption probes). Validation relies entirely on mathematical markers (`7*7 -> 49`) and metadata correlation.
2. **Strict Scope Control**: No active probe can bypass `ScopedTransport`. Redirects to third-party domains are halted before TCP handshakes occur.
3. **Zero Plaintext Secret Exposure**: Session credentials and cookies are isolated in OS-permissioned `auth_secrets.json` and are never rendered into logs, reports, or LLM prompts.
4. **False Positive Control**: Input reflection is explicitly audited. If a probe's payload is reflected verbatim without calculated evaluation, the candidate is flagged as `needs_manual_review` rather than verified.
5. **No Auto-Submission**: In accordance with `AGENTS.md`, verified findings remain in `reports/` and are never submitted to bug bounty platforms without manual human review and explicit approval.
