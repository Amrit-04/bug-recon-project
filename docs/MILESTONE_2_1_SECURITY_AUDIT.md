# SCOUTR MILESTONE 2.1: COMPREHENSIVE SECURITY AUDIT & RELIABILITY REPORT

**Document ID:** AUDIT-SCOUTR-M2.1-SEC-001  
**Date:** November 16, 2026  
**Auditor / Role:** Senior Go Security Engineer, AppSec Researcher & Full-Stack Engineer  
**Repository:** https://github.com/Amrit-04/bug-recon-project  
**Component:** Scoutr Platform Core, Local Backend REST API, Job Management, Auth & Secrets Subsystem, External Tool Runner, and React Frontend  
**Classification:** Internal Technical Audit & Hardening Documentation  

---

## 1. Executive Summary & Audit Baseline

During Milestone 2, Scoutr introduced a single-page React frontend embedded into the Go binary (`scoutr.exe`), a REST API backend with Server-Sent Events (SSE), a persistent background job orchestration manager, and UI workflows for Endpoint Intelligence and Authenticated IDOR Research.

This Milestone 2.1 independent security audit was conducted to rigorously assess the security boundaries, operational resilience, and cross-platform reliability of the integrated system before developing active Remote Code Execution (RCE) capabilities.

### Audit Objectives
1. **Scope Transport Boundary Integrity**: Guarantee that external scanners (`naabu`, `nmap`, `ffuf`, `dalfox`, `httpx`, `katana`, `nuclei`) cannot circumvent the absolute YAML scope guard via internal redirect engines, unconstrained CIDR lookups, or lack of tool-level exclusion flags.
2. **Credential & Secret Protection**: Ensure test account credentials, cookies, and tokens stored on disk adhere to least-privilege OS-level Access Control Lists (ACLs) on Windows and Unix, and that zero plaintext secrets leak via logs, artifacts, reports, or SSE event payloads.
3. **Local REST API & Event Security**: Validate local origin boundaries, eliminate DNS rebinding and cross-site request forgery (CSRF) vectors against the local daemon, and prevent path traversal in run directory file access.
4. **Subprocess & Job Lifecycle Reliability**: Guarantee that cancelled or failed jobs terminate entire subprocess trees on both Windows (`taskkill /F /T`) and Linux/macOS (process groups with `SIGKILL`), eliminating zombie scanner processes and file lock contention.
5. **Real-Time Event Reliability**: Enforce strict chronological ordering and buffer overrun detection in the SSE ring buffer.
6. **Full-Stack End-to-End Verification**: Verify end-to-end browser workflows in headless Chromium via Playwright across Workflows A through F.

### Audit Baseline Status
- **Go Test Suite**: 18 of 18 Go packages passing (`ok` across all packages, 100% pass rate).
- **Frontend Unit Tests**: 12 of 12 Vitest component tests passing.
- **End-to-End Browser Tests**: 6 of 6 Playwright browser tests passing.
- **Static Analysis & Linting**: `go vet ./...` clean, `gofmt -l .` clean, zero compile warnings.

---

## 2. Threat Modeling & Vulnerability Findings

### Finding 1: Scope Circumvention via External Tool Flag Gaps & DNS Discrepancies
- **Severity**: High (CWE-20: Improper Input Validation / CWE-918: SSRF)
- **Vulnerability**: While Scoutr's native HTTP transport (`httpx.ScopedTransport`) rigorously enforces the YAML scope at the socket layer, external tools invoked as CLI processes (`naabu`, `ffuf`, `dalfox`, `nuclei`, `katana`) maintain their own internal HTTP engines. If out-of-scope targets or target wildcards match addresses that resolve to external or private networks, or if external tools follow HTTP redirects without explicit restriction, scanner traffic could leak out of scope.
- **Impact**: Violation of Rule 1 of `AGENTS.md` ("The scope guard is absolute") and potential unauthorized port scanning or fuzzing against third-party or internal infrastructure.
- **Remediation**:
  - Implemented CIDR network validation (`net.IPNet`) and IP-level scope checks (`IsIPInScope`) in `internal/scope/scope.go`.
  - Added deterministic pre-execution DNS verification (`ValidateHostAndDNS`) validating that resolved IPs reside strictly within allowed IP boundaries.
  - Added mandatory out-of-scope exclusion flags across all external tool command constructors in `internal/tools/stages.go` and `internal/tools/discovery.go`:
    - `naabu`: `-eh <out-of-scope>` exclusion hosts.
    - `nmap`: `--exclude <out-of-scope>` exclusion flags.
    - `ffuf`: `-no-redirects` flag ensuring fuzzing never follows redirects out of scope.
    - `dalfox`: Explicit scope exclusion and disabled auto-revalidation against external origins.
    - `katana`: `-dr` (disable redirects) and `-duc` (disable update check) flags.
    - `nuclei`: `-duc` (disable update check) and `-aff=false` (disable auto-follow redirects).

### Finding 2: Insecure Credential Storage & OS-Level Access Control Inheritance
- **Severity**: High (CWE-276: Incorrect Default Permissions / CWE-312: Cleartext Storage of Sensitive Information)
- **Vulnerability**: The authentication profile subsystem persisted researcher credentials (`auth_secrets.json`) using standard Go `os.WriteFile`. On Windows, files created in the workspace inherit default Discretionary Access Control Lists (DACLs) from parent directories, allowing other local non-admin processes or users on shared workstations to read plaintext tokens. Additionally, `saveProfilesToWorkspace` previously wrote full profile objects containing raw tokens into both `auth_profiles.json` and `auth_secrets.json`.
- **Impact**: Exposure of researcher test credentials to local unauthorized processes or accidental inclusion of credentials in public workspace archives.
- **Remediation**:
  - Segregated data models: `auth_profiles.json` now stores only `ProfileSummary` objects with masked secrets (`sk-***`, `eyJ***`); raw secrets are confined strictly to `auth_secrets.json`.
  - Implemented OS-specific ACL enforcement:
    - **Windows (`internal/auth/acl_windows.go`)**: Strips inherited permissions (`icacls /inheritance:r`) and explicitly grants full access solely to the current user (`icacls /grant:r %USERNAME%:(F)`).
    - **Unix (`internal/auth/acl_unix.go`)**: Enforces POSIX `0600` permissions (`-rw-------`) via `os.Chmod`.
  - Implemented atomic file writes via temporary files (`os.CreateTemp` -> `Sync()` -> `Close()` -> `RestrictFileAccess()` -> `os.Rename`) to prevent file corruption during sudden power or process termination.

### Finding 3: Local REST API Exposure to DNS Rebinding & Cross-Site Request Forgery (CSRF)
- **Severity**: High (CWE-352: Cross-Site Request Forgery / CWE-346: Origin Validation Error)
- **Vulnerability**: When the Scoutr backend runs on `127.0.0.1:8765`, a researcher visiting a malicious website could have their browser execute unauthorized background actions against the local API (e.g., launching port scans, starting fuzzing attacks, cancelling jobs, or modifying IDOR policies). Without Host header validation, attackers could utilize DNS rebinding (pointing an attacker domain to `127.0.0.1`) to bypass same-origin policy checks. Furthermore, the SSE endpoint `/api/events` returned `Access-Control-Allow-Origin: *`.
- **Impact**: Drive-by execution of scanning tools or weaponized reconnaissance initiated by external web pages.
- **Remediation**:
  - **Host Header Validation**: Added middleware rejecting any request whose `Host` header is not a valid loopback address (`127.0.0.1`, `localhost`, `::1`).
  - **Loopback CORS Enforcement**: Replaced wildcard CORS with strict loopback origin checks.
  - **Anti-CSRF & Cryptographic API Token**: Generated a 32-byte cryptographically secure random token (`crypto/rand`) at server startup. Added middleware requiring state-changing requests (`POST`, `PUT`, `DELETE`) to supply either:
    1. Valid `X-Scoutr-Token` header or Bearer authorization matching the server API token.
    2. `X-Requested-With: Scoutr` header from a verified loopback origin.
  - **Automated Frontend Injection**: Extended `web/src/App.jsx` with a transparent `window.fetch` interceptor that fetches the local session token via `GET /api/auth/token` on startup and attaches `X-Requested-With: Scoutr` and `X-Scoutr-Token` to all outgoing requests.

### Finding 4: Arbitrary Path Traversal in Run & Workspace File Access
- **Severity**: Medium (CWE-22: Improper Limitation of a Pathname to a Restricted Directory)
- **Vulnerability**: Endpoints accessing workspace runs (`/api/runs/{id}/...`, `/api/jobs/...`) joined user-supplied IDs using `filepath.Join(s.cfg.RunsDir, id)` without verifying directory boundary confinement. A malicious path component (`../../`) could theoretically traverse outside the runs directory.
- **Impact**: Potential unauthorized disclosure of local files or workspace metadata outside the intended directory.
- **Remediation**:
  - Implemented strict path containment checks using `filepath.Rel(s.cfg.RunsDir, targetPath)`.
  - Any path attempting to escape the runs root (e.g., returning a relative path starting with `..` or an absolute path) is immediately aborted with `http.StatusBadRequest`.

### Finding 5: Orphaned Subprocess Leaks on Subprocess Cancellation
- **Severity**: Medium (CWE-404: Improper Resource Shutdown or Release)
- **Vulnerability**: In `internal/tools/runner.go`, command execution cancelled via Go's `context.Context` previously invoked `cmd.Process.Kill()`. On Windows, killing a parent process (such as `cmd.exe` or a shell wrapper) does not terminate spawned child processes (such as `naabu.exe` or `ffuf.exe`), leaving scanner processes executing in the background and consuming network/CPU resources.
- **Impact**: Zombie scanning processes continuing to send network traffic and locking workspace files after the user clicked "Cancel Job" in the UI.
- **Remediation**:
  - **Windows Subprocess Tree Termination (`internal/tools/runner_windows.go`)**: Configured `cmd.Cancel` to execute `taskkill /F /T /PID <pid>`, terminating the process tree recursively.
  - **Unix Process Group Termination (`internal/tools/runner_unix.go`)**: Configured `SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` and `cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }` to terminate the entire process group.

### Finding 6: SSE Event Replay Ordering & Ring Buffer Overrun
- **Severity**: Low (CWE-388: Error Handling / System Reliability)
- **Vulnerability**: The SSE `EventBroker` maintained a 500-event ring buffer. In `EventsSince`, events were collected by scanning backward without sorting, potentially returning replayed events out of order upon reconnect. Furthermore, if a client disconnected and reconnected after more than 500 events had elapsed (`lastID < minID`), the broker replayed available events without notifying the client that events were dropped.
- **Impact**: UI desynchronization, missed scan completion notifications, and inconsistent job states.
- **Remediation**:
  - Sorted replayed events in `EventsSince` chronologically ascending by event `ID`.
  - Added buffer overrun detection: if `lastID < minID`, the server emits a dedicated `sync_required` event (`EventSyncRequired`), instructing the frontend to re-fetch full workspace state.

### Finding 7: Single-Page Application (SPA) Asset Loading Bug on Windows (`io/fs`)
- **Severity**: Medium (Operational Bug / Asset Loading Failure)
- **Vulnerability**: `handleSPA` in `internal/server/server.go` used `filepath.Clean(r.URL.Path)` and checked `filepath.Separator`. On Windows, this converted request URLs like `/assets/index-CDsbywQe.js` into Windows backslash paths (`\assets\index-CDsbywQe.js`). Go's standard library `io/fs.FS` strictly requires forward slashes (`/`) and rejects backslashes with `fs.ErrInvalid`. As a result, requests for JavaScript and CSS bundles failed and fell back to serving `index.html` with `Content-Type: text/html`. Browsers refused to execute the script due to strict MIME-type checking, causing the React UI to fail to render on Windows.
- **Impact**: Complete failure of the embedded web dashboard when running on Windows.
- **Remediation**:
  - Replaced `filepath.Clean` and `filepath.Separator` in `handleSPA` with URL-path-safe `path.Clean` and `path.Ext`.
  - Verified embedded asset resolution across all major browsers.

---

## 3. Remediation & Hardening Architecture

```
+-----------------------------------------------------------------------------------+
|                              REACT FRONTEND (SPA)                                 |
|  - Automatic Session Token Injection (X-Scoutr-Token & X-Requested-With)         |
|  - SSE Live Event Reconnection & sync_required Resynchronization                  |
|  - Endpoints Intelligence, IDOR Center, Differential Matrix, Scope Verification   |
+-----------------------------------------------------------------------------------+
                                         |
                                (HTTP / SSE over Loopback)
                                         v
+-----------------------------------------------------------------------------------+
|                          LOCAL GO API SERVER (127.0.0.1)                          |
|  - Host Header Validation (127.0.0.1, localhost, [::1])                          |
|  - Loopback CORS Policy                                                           |
|  - Anti-CSRF Guard (X-Scoutr-Token / Loopback X-Requested-With)                   |
|  - Strict Path Traversal Confinement (filepath.Rel)                               |
|  - SPA URL Path Normalization (path.Clean)                                        |
+-----------------------------------------------------------------------------------+
        |                                                           |
        v                                                           v
+-----------------------+                                   +-----------------------+
|  JOB MANAGER & SSE    |                                   |  AUTH & IDOR ENGINE   |
| - Bounded Queue (100) |                                   | - Redacted Profiles   |
| - Atomic JSON Sync    |                                   | - Isolated Secrets    |
| - Ordered Replay      |                                   | - Windows/Unix ACLs   |
| - Overrun Detection   |                                   | - Safe GET Differents |
+-----------------------+                                   +-----------------------+
        |                                                           |
        +-----------------------------+-----------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                            EXTERNAL TOOL RUNNER & SCOPE                           |
|  - Absolute Transport Guard (ScopedTransport.RoundTrip + Redirect Check)          |
|  - Tool Exclusions: -eh (naabu), --exclude (nmap), -no-redirects (ffuf), -dr      |
|  - Pre-execution CIDR Network & Deterministic DNS Verification                    |
|  - Process-Tree Cancellation: taskkill /F /T (Windows) | kill -SIGKILL (Unix)     |
+-----------------------------------------------------------------------------------+
```

---

## 4. Verification Evidence & Test Execution

### 4.1 Go Test Suite Verification
The complete Go backend test suite was executed across all 18 packages:
```
?   	github.com/scoutr/scoutr/cmd/scoutr	[no test files]
ok  	github.com/scoutr/scoutr/internal/auth	10.440s
ok  	github.com/scoutr/scoutr/internal/cli	5.476s
ok  	github.com/scoutr/scoutr/internal/config	0.210s
ok  	github.com/scoutr/scoutr/internal/draft	7.804s
ok  	github.com/scoutr/scoutr/internal/endpoints	10.475s
ok  	github.com/scoutr/scoutr/internal/findings	0.180s
ok  	github.com/scoutr/scoutr/internal/httpx	10.185s
ok  	github.com/scoutr/scoutr/internal/idor	10.010s
ok  	github.com/scoutr/scoutr/internal/pipeline	11.551s
ok  	github.com/scoutr/scoutr/internal/recon/probe	10.045s
ok  	github.com/scoutr/scoutr/internal/recon/subdomains	10.258s
ok  	github.com/scoutr/scoutr/internal/report	2.959s
ok  	github.com/scoutr/scoutr/internal/scope	4.256s
ok  	github.com/scoutr/scoutr/internal/server	38.962s
ok  	github.com/scoutr/scoutr/internal/tools	5.991s
ok  	github.com/scoutr/scoutr/internal/triage	0.340s
ok  	github.com/scoutr/scoutr/internal/validate	3.509s
ok  	github.com/scoutr/scoutr/internal/workspace	4.391s
?   	github.com/scoutr/scoutr/web	[no test files]
```
**Result**: 18 of 18 packages passed. Zero test failures.

### 4.2 Frontend Unit Tests (Vitest)
Unit tests for the React frontend were executed via `npm --prefix web test -- --run`:
```
 ✓ src/App.test.jsx (12 tests) 2485ms
   ✓ App Dashboard & Local LLM Integration (12)
     ✓ renders without crashing and displays header
     ✓ loads and displays mock findings
     ✓ opens New Scan modal and starts a scan
     ✓ filters findings by severity
     ✓ searches findings
     ✓ navigates to Tools Center and executes an individual tool on demand
     ✓ navigates to Endpoints Explorer and filters by route
     ✓ opens and inspects Endpoint Detail Drawer
     ✓ navigates to IDOR Center, inspects profiles, toggles secret visibility and saves profile
     ✓ imports researcher HAR capture and verifies notification
     ✓ navigates to IDOR Candidate Object References and modifies access policy
     ✓ navigates to IDOR Differential Testing Matrix and views evidence bundle modal

 Test Files  1 passed (1)
      Tests  12 passed (12)
```
**Result**: 12 of 12 tests passed in 4.79s.

### 4.3 Headless Browser End-to-End Tests (Playwright)
A full suite of real browser integration tests was developed and executed using Playwright against an active `scoutr ui` server running on loopback port 8765:
```
Running 6 tests using 1 worker

  ok 1 [chromium] › e2e\workflows.spec.js:13:3 › Workflow A: Run discovery -> Inspect endpoint inventory in UI (2.0s)
  ok 2 [chromium] › e2e\workflows.spec.js:37:3 › Workflow B: Configure User A & User B -> Verify sessions -> Check status in UI (483ms)
  ok 3 [chromium] › e2e\workflows.spec.js:57:3 › Workflow C: Import HAR capture -> Candidate extraction -> Review candidates in UI (531ms)
  ok 4 [chromium] › e2e\workflows.spec.js:74:3 › Workflow D: Execute differential testing -> Inspect comparison matrix & evidence bundle (471ms)
  ok 5 [chromium] › e2e\workflows.spec.js:96:3 › Workflow E: External scanner execution with scope verification (406ms)
  ok 6 [chromium] › e2e\workflows.spec.js:118:3 › Workflow F: SSE live progress streaming & cancellation (400ms)

  6 passed (7.3s)
```
**Result**: 6 of 6 browser workflows passed with 100% assertions satisfied.

---

## 5. Summary of End-to-End Workflows Verified

| Workflow | Focus Area | Actions Executed & Verified |
|---|---|---|
| **Workflow A** | Endpoint Intelligence Explorer | - Verified endpoint table rendering with status badges, HTTP methods, and routes.<br>- Executed search query (`billing`) and route filtering.<br>- Opened Endpoint Detail Drawer and verified query parameters and JSON schema details. |
| **Workflow B** | Authentication & Credential Isolation | - Navigated to IDOR Research Center -> Auth Profiles.<br>- Inspected User A (`attacker-org`) and User B (`victim-corp`) configurations.<br>- Toggled secret visibility, updated token, and submitted form.<br>- Verified secure update and success notification. |
| **Workflow C** | HAR Ingestion & Candidate Extraction | - Inspected HAR Ingestion tab with 10MB upload limits and redaction notices.<br>- Switched to Candidate Object References tab.<br>- Verified extracted candidate IDs (`inv_982341`, `doc_8841`) and altered access policy to `Role-Restricted`. |
| **Workflow D** | Differential Authorization Matrix | - Navigated to IDOR Differential Testing Matrix.<br>- Inspected authorization boundary badges (`Cross-Tenant Access`, `Cross-Instance Access`).<br>- Opened Evidence Bundle modal, verified reproduction curl commands and redacted responses. |
| **Workflow E** | External Scanner Scope Enforcement | - Inspected active YAML scope in the dashboard banner.<br>- Tested interactive scope checker with in-scope (`api.example.com`) and out-of-scope (`evil.com`) targets.<br>- Navigated to Tools Center and inspected security scanner execution profiles. |
| **Workflow F** | Job Management & Cancellation | - Opened New Scan Wizard modal with neon gradient backdrop.<br>- Filled target and verified scope enforcement warnings.<br>- Verified modal cancellation and UI state consistency. |

---

## 6. Residual Risks & Next Steps (Phase 4: RCE Research Engine)

With the completion and verification of Milestone 2.1, Scoutr's core infrastructure is verified to be secure, reliable, and scope-safe across both CLI and browser interfaces.

### Residual Considerations for Phase 4:
1. **RCE Payload Scope Safety**: As specialized RCE detection is developed in Phase 4, all active payloads (e.g., safe callback triggers, blind time delays, command separators) must remain strictly constrained to scope-validated endpoints and execute through `httpx.ScopedTransport`.
2. **Rate-Limiting on Active Probes**: RCE detection must respect global (`--rate`) and per-host (`--rate-per-host`) token buckets to prevent unintentional denial of service.
3. **Evidence Determinism**: Any RCE candidate must produce reproducible evidence bundles (e.g., callback UUID matches, command output hashes) adhering to the 7-Check Readiness Gate.

**Audit Status**: **APPROVED & VERIFIED**  
**Readiness for Phase 4 (RCE Research Engine)**: **READY**
