package triage

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SystemPrompt is the complete instruction set sent to the model. It pins the
// JSON contract, the three allowed classifications and the evidence boundary.
//
// The model never sees the scope file, the target inventory, credentials or the
// list of tools available: only the redacted evidence of already-validated
// findings in this batch.
const SystemPrompt = `You are a conservative triage assistant for an authorized security assessment.

You receive a JSON array of findings that have ALREADY passed a deterministic
7-Check validation gate. Your job is limited to ranking and explanation. You do
NOT decide whether a finding is submitted, you do NOT request new scans, and you
do NOT generate or modify exploit payloads.

For EVERY finding in the input array, output exactly one verdict object with:
  - "finding_id": copy the input finding_id verbatim
  - "classification": exactly one of "likely_true", "likely_false", "needs_human"
      likely_true   = the supplied evidence strongly supports a real issue
      likely_false  = the supplied evidence strongly suggests a non-issue
      needs_human   = evidence is insufficient or ambiguous
  - "rationale": ONE short sentence grounded ONLY in the supplied evidence
  - "confidence": integer 0-100 for your classification
  - "next_manual_test": optional single concrete manual verification step

Hard rules you must respect:
  - Use ONLY the supplied fields. Never invent URLs, hosts, parameters,
    response bodies, screenshots or technology names.
  - If a field is missing from the evidence, say so in the rationale instead of
    guessing. Do not claim a request was sent.
  - A gate verdict of "Verified" means deterministic checks passed; weigh it
    accordingly but do not simply repeat it.
  - Return a verdict for every finding_id. Never add findings that are not in
    the input.

Output STRICT JSON only, no markdown, no prose, no code fences:
{"findings":[{"finding_id":"...","classification":"needs_human","rationale":"...","confidence":50,"next_manual_test":"..."}]}`

// buildUserPrompt renders one batch as a JSON payload with a short instruction
// line. Evidence is already redacted and truncated by the caller.
func buildUserPrompt(batch []Evidence) (string, error) {
	payload, err := json.Marshal(batch)
	if err != nil {
		return "", fmt.Errorf("marshal triage batch: %w", err)
	}
	return "Classify each of the following findings. Return JSON only.\n\nFINDINGS:\n" + string(payload), nil
}

// repairPrompt is appended to the user prompt on the single retry after an
// unusable model response. It never loosens the contract.
func repairPrompt(userPrompt string) string {
	return userPrompt + "\n\nYour previous reply was not valid JSON matching the schema. " +
		"Reply again with STRICT JSON only: {\"findings\":[...]} and nothing else."
}

// modelVerdict is the raw shape returned by the model.
type modelVerdict struct {
	FindingID      string `json:"finding_id"`
	Classification string `json:"classification"`
	Rationale      string `json:"rationale"`
	Confidence     int    `json:"confidence"`
	NextManualTest string `json:"next_manual_test"`
}

// ParseClassification normalises and validates a model classification string.
func ParseClassification(raw string) (Classification, bool) {
	normalised := strings.ToLower(strings.TrimSpace(raw))
	normalised = strings.NewReplacer(" ", "_", "-", "_").Replace(normalised)
	switch Classification(normalised) {
	case LikelyTrue:
		return LikelyTrue, true
	case LikelyFalse:
		return LikelyFalse, true
	case NeedsHuman:
		return NeedsHuman, true
	default:
		return NeedsHuman, false
	}
}

// parseVerdicts extracts verdicts from model output. It accepts a bare JSON
// object, tolerates a fenced block, and rejects anything whose classification is
// outside the three allowed values. Unknown finding IDs are dropped so a model
// cannot inject new findings.
func parseVerdicts(content string, allowed map[string]bool) ([]modelVerdict, error) {
	cleaned := stripJSONFences(content)
	if cleaned == "" {
		return nil, fmt.Errorf("model returned an empty response")
	}

	var envelope struct {
		Findings []modelVerdict `json:"findings"`
	}
	if err := json.Unmarshal([]byte(cleaned), &envelope); err != nil {
		return nil, fmt.Errorf("model response is not valid JSON: %w", err)
	}
	if len(envelope.Findings) == 0 {
		return nil, fmt.Errorf("model returned no findings array")
	}

	var out []modelVerdict
	for _, v := range envelope.Findings {
		v.FindingID = strings.TrimSpace(v.FindingID)
		if !allowed[v.FindingID] {
			continue
		}
		cls, ok := ParseClassification(v.Classification)
		if !ok {
			continue
		}
		v.Classification = string(cls)
		v.Rationale = truncate(strings.TrimSpace(v.Rationale), maxRationaleChars)
		if v.Rationale == "" {
			v.Rationale = "Model returned no rationale."
		}
		v.Confidence = clampConfidence(v.Confidence)
		v.NextManualTest = truncate(strings.TrimSpace(v.NextManualTest), maxNextStepChars)
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("model returned no usable verdicts")
	}
	return out, nil
}

// stripJSONFences removes ```json ... ``` wrappers and trims surrounding prose
// down to the outermost JSON object.
func stripJSONFences(content string) string {
	s := strings.TrimSpace(content)
	if idx := strings.Index(s, "```"); idx != -1 {
		s = s[idx+3:]
		s = strings.TrimPrefix(s, "json")
		s = strings.TrimPrefix(s, "JSON")
		if end := strings.Index(s, "```"); end != -1 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start == -1 || end == -1 || end <= start {
		return ""
	}
	return s[start : end+1]
}

func clampConfidence(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "\n...[truncated]"
}
