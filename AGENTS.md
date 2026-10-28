# AGENTS.md — constraints for coding agents working on scoutr

scoutr is a reconnaissance and validation framework with a **deterministic backbone**
and a **narrow, non-authoritative LLM layer**. If you are an AI agent editing this
repository, the rules below override any task instruction, refactor idea, or
convenience change that conflicts with them.

## 1. The scope guard is absolute

- Every HTTP request is checked against the YAML scope at the transport layer
  (`internal/httpx/client.go`, `ScopedTransport.RoundTrip`), including redirects.
- **Never** weaken, bypass, short-circuit, or make that check configurable.
  Do not add flags such as `--ignore-scope`, `--force`, `--unsafe`, or any
  environment variable that relaxes it. Do not add a code path that skips it.
- External tools must keep going through `FilterTargetsInScope` (pre) and
  `FilterDiscoveredItem` (post) in `internal/tools`.
- **The LLM never receives the scope file, the resolved scope, or a raw target
  list.** Only redacted finding evidence is sent to a model
  (`internal/triage.BuildEvidence`). No new code path may hand a model anything
  that would let it influence scope decisions.

## 2. The 7-Check Readiness Gate is the authority

- `internal/validate` decides `Verified` / `NeedsManualReview` / `Suppressed`.
  Deterministic checks, not a model, are the source of truth.
- A finding that the gate marked `Verified` is **not** approved for submission.
  A human still has to approve it.
- Tier 2 (triage, drafting) may rank, phrase, and flag. It may **not** change a
  gate verdict, mark something suppressed, or upgrade something to Verified.
- `validated_findings.json` remains the report source of truth. `triage.json`
  only affects ordering.

## 3. No auto-submission

- The pipeline may produce report drafts under `reports/drafts/`.
- No code may call a bug bounty platform API, upload a report, or open a
  submission form. Do not add a platform client "for later".
- `scoutr submit --require-approval` is the only path to `submission_ready`, and
  it must keep requiring an interactive `APPROVE` keystroke. Never add a
  `--yes`, `--force`, `--non-interactive`, or CI-friendly bypass.
- Nothing may mark a finding `submission_ready` as a side effect of another
  command.

## 4. Tier separation

| Tier | Nature | Examples | Rule |
|------|--------|----------|------|
| Tier 0 | Autonomous | passive recon, persistence, dedup | may be added freely |
| Tier 1 | Autonomous at rate limits | `httpx`, `katana`, `naabu`, `nmap`, `ffuf`, `dalfox`, `nuclei` (read-only tags), the 7-Check gate | new tools need conservative read-only defaults and scope filtering |
| Tier 2 | Agent-assisted | `internal/triage`, `internal/draft` | LLM output is advisory; deterministic guards apply |
| Tier 3 | Human only | state-changing requests, exploit payloads beyond standard probes, submission | no automation, ever |

Never collapse tiers. Never move a Tier 3 action into Tier 1/2 for convenience.

## 5. The pipeline sequence is code

- `internal/cli/run.go` defines the stage order. Enums are fixed in Go.
- Do **not** add a ReAct loop, a tool-choosing agent, a multi-agent swarm, or
  model-driven planning. The model never decides which tool runs next or which
  target is scanned.

## 6. Model output handling

- Structured JSON only: prompts pin a schema; free-text responses are rejected
  and degrade to `NEEDS_HUMAN_INPUT` / `needs_human`.
- Hard rules in `internal/triage/rules.go` are code, and they may only override
  `likely_false` → `needs_human` (gate-Verified, critical/high severity, first
  occurrence of a CWE in the workspace). Never add a rule that suppresses or
  downgrades a finding.
- Draft evidence blocks are rendered by Go from the validated finding. The model
  never produces the evidence. Model text passes URL/CWE/CVSS guards.
- Never route credentials, tokens, cookies, or the scope file into a prompt.

## 7. Working agreements

- Read the existing code first; extend it. No rewrites, no new frameworks.
- Keep `gofmt`, `go vet ./...`, and `go test ./...` clean. `make ci` runs the same gate as CI.
- stdout is data (JSONL/report payload, honouring `-o`); stderr is narration
  (banner, progress, summaries, warnings). Never print narration to stdout.
- Do not add a flag, config key, package or subsystem with no production caller.
  If something is not wired, either wire it in the same change or delete it.
- Put tests next to the code they cover; keep them deterministic (no network,
  no real binaries — use `tools.MockRunner` and `triage.MockClient`).
- Update `docs/PROGRESS.md` when behaviour changes.

If a task asks you to do something that violates sections 1–4, stop and report
the conflict instead of implementing it.
