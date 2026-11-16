package rce

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

func TestClassifier(t *testing.T) {
	classifier := NewClassifier()

	eps := []*endpoints.Endpoint{
		{
			Origin:           "https://example.com",
			URL:              "https://example.com/api/v1/diag/ping",
			NormalizedRoute:  "/api/v1/diag/ping",
			Methods:          []string{"POST"},
			QueryParams:      []string{"target"},
			BodyFields:       []string{"host", "count"},
			TechFingerprints: []string{"Linux", "Go"},
		},
		{
			Origin:           "https://example.com",
			URL:              "https://example.com/render/template",
			NormalizedRoute:  "/render/template",
			Methods:          []string{"GET"},
			QueryParams:      []string{"template", "format"},
			TechFingerprints: []string{"Python", "Jinja2"},
		},
		{
			Origin:          "https://example.com",
			URL:             "https://example.com/api/v1/upload/document",
			NormalizedRoute: "/api/v1/upload/document",
			Methods:         []string{"POST"},
			ContentTypes:    []string{"multipart/form-data"},
			BodyFields:      []string{"file", "attachment"},
		},
		{
			Origin:          "https://example.com",
			URL:             "https://example.com/api/v1/users/{id}",
			NormalizedRoute: "/api/v1/users/{id}",
			Methods:         []string{"GET"},
			QueryParams:     []string{"page"},
		},
	}

	cands := classifier.ClassifyEndpoints("example.com", eps)
	for _, c := range cands {
		t.Logf("Candidate: ID=%s, Cat=%s, Route=%s", c.ID, c.Category, c.Route)
	}
	if len(cands) != 3 {
		t.Fatalf("expected 3 candidates (cmd, ssti, file), got %d", len(cands))
	}

	foundCmd := false
	foundSSTI := false
	foundFile := false

	for _, c := range cands {
		if c.Category == CategoryCommandInjection {
			foundCmd = true
			if c.Confidence != ConfidenceHigh {
				t.Errorf("expected high confidence for command injection with route and params, got %s", c.Confidence)
			}
		}
		if c.Category == CategorySSTI {
			foundSSTI = true
			if c.Confidence != ConfidenceHigh {
				t.Errorf("expected high confidence for SSTI, got %s", c.Confidence)
			}
		}
		if c.Category == CategoryFileProcessing {
			foundFile = true
		}
	}

	if !foundCmd || !foundSSTI || !foundFile {
		t.Errorf("failed to classify expected categories: cmd=%v, ssti=%v, file=%v", foundCmd, foundSSTI, foundFile)
	}
}

func TestChainDetector(t *testing.T) {
	detector := NewChainDetector()

	candUpload := &RCECandidate{
		ID:             "cand_upload",
		Origin:         "https://example.com",
		Route:          "/api/upload/doc",
		HTTPMethod:     "POST",
		Category:       CategoryFileProcessing,
		RelevantParams: []string{"doc_id", "file"},
	}

	candPreview := &RCECandidate{
		ID:             "cand_preview",
		Origin:         "https://example.com",
		Route:          "/api/convert/preview",
		HTTPMethod:     "GET",
		Category:       CategoryFileProcessing,
		RelevantParams: []string{"doc_id"},
	}

	candidates := []*RCECandidate{candUpload, candPreview}
	detector.CorrelateChains(candidates)

	if len(candUpload.AssociatedChains) != 1 {
		t.Fatalf("expected 1 associated chain on upload candidate, got %d", len(candUpload.AssociatedChains))
	}
	if len(candPreview.AssociatedChains) != 1 {
		t.Fatalf("expected 1 associated chain on preview candidate, got %d", len(candPreview.AssociatedChains))
	}

	chain := candUpload.AssociatedChains[0]
	if len(chain.Steps) != 2 {
		t.Errorf("expected 2 chain steps, got %d", len(chain.Steps))
	}
}

func TestAdvisorySemVer(t *testing.T) {
	// Parse semver
	v1, err := ParseSemVer("5.3.17")
	if err != nil {
		t.Fatalf("failed to parse v1: %v", err)
	}
	v2, err := ParseSemVer("5.3.18")
	if err != nil {
		t.Fatalf("failed to parse v2: %v", err)
	}

	if v1.Compare(v2) >= 0 {
		t.Errorf("expected 5.3.17 < 5.3.18")
	}

	// Range matches
	if !MatchesRange("5.3.17", ">= 5.3.0, < 5.3.18") {
		t.Errorf("expected 5.3.17 to match range '>= 5.3.0, < 5.3.18'")
	}
	if MatchesRange("5.3.18", ">= 5.3.0, < 5.3.18") {
		t.Errorf("expected 5.3.18 NOT to match range '>= 5.3.0, < 5.3.18'")
	}
	if !MatchesRange("5.2.19", ">= 5.3.0, < 5.3.18; >= 5.2.0, < 5.2.20") {
		t.Errorf("expected 5.2.19 to match multi-range")
	}
	if MatchesRange("5.2.20", ">= 5.3.0, < 5.3.18; >= 5.2.0, < 5.2.20") {
		t.Errorf("expected 5.2.20 NOT to match multi-range")
	}
}

func TestAdvisoryCorrelation(t *testing.T) {
	registry := NewAdvisoryRegistry()

	// Candidate with vulnerable version
	vulnCand := &RCECandidate{
		ID:                 "cand_spring_vuln",
		Origin:             "https://example.com",
		Route:              "/api/v1/order/submit",
		HTTPMethod:         "POST",
		Category:           CategoryCommandInjection,
		RelevantBodyFields: []string{"customer_name", "item_code"},
		RelevantTech:       []string{"Spring Framework 5.3.17", "Java 17"},
	}

	matches := registry.CorrelateCandidate(vulnCand)
	if len(matches) == 0 {
		t.Fatalf("expected Spring4Shell advisory match, got none")
	}

	match := matches[0]
	if match.Advisory.ID != "CVE-2022-22965" {
		t.Errorf("expected CVE-2022-22965, got %s", match.Advisory.ID)
	}
	if match.ProgressionTier != TierComponentReachable {
		t.Errorf("expected TierComponentReachable, got %s", match.ProgressionTier)
	}

	// Candidate with fixed version
	fixedCand := &RCECandidate{
		ID:                 "cand_spring_fixed",
		Origin:             "https://example.com",
		Route:              "/api/v1/order/submit",
		HTTPMethod:         "POST",
		Category:           CategoryCommandInjection,
		RelevantBodyFields: []string{"customer_name"},
		RelevantTech:       []string{"Spring Framework 5.3.18"},
	}

	fixedMatches := registry.CorrelateCandidate(fixedCand)
	if len(fixedMatches) != 0 {
		t.Errorf("expected 0 matches for patched Spring 5.3.18, got %d", len(fixedMatches))
	}
}

func TestPrioritizer(t *testing.T) {
	prioritizer := NewPrioritizer()

	cand1 := &RCECandidate{
		ID:             "cand1",
		Route:          "/diag/ping",
		Category:       CategoryCommandInjection,
		RelevantParams: []string{"host", "count"},
	}

	cand2 := &RCECandidate{
		ID:             "cand2",
		Route:          "/view/page",
		Category:       CategorySSTI,
		RelevantParams: []string{"page"},
	}

	candidates := []*RCECandidate{cand2, cand1}
	prioritizer.PrioritizeCandidates(candidates)

	// cand1 has command injection (base 30) + 2 params (25) = higher score
	if candidates[0].ID != "cand1" {
		t.Errorf("expected cand1 to be ranked first, got %s", candidates[0].ID)
	}
	if candidates[0].PriorityScore < candidates[1].PriorityScore {
		t.Errorf("expected cand1 score (%d) > cand2 score (%d)", candidates[0].PriorityScore, candidates[1].PriorityScore)
	}
	if len(candidates[0].ScoreBreakdown.Explanations) == 0 {
		t.Errorf("expected score breakdown explanations to be populated")
	}
}

func TestValidator_DeterministicChecks(t *testing.T) {
	// Setup test server with 3 scenarios:
	// 1. /ssti_vuln: Evaluates math expressions ({{7*7}} -> 49, {{7*8}} -> 56)
	// 2. /reflection_trap: Echoes probe verbatim without evaluation
	// 3. /static_noise: Response always contains "49"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		path := r.URL.Path

		switch path {
		case "/ssti_vuln":
			if strings.Contains(q, "{{7*7}}") {
				fmt.Fprint(w, "<html><body>Result: 49</body></html>")
			} else if strings.Contains(q, "{{7*8}}") {
				fmt.Fprint(w, "<html><body>Result: 56</body></html>")
			} else {
				fmt.Fprint(w, "<html><body>Result: standard</body></html>")
			}
		case "/reflection_trap":
			// Literal echo
			fmt.Fprintf(w, "<html><body>Searched for: %s</body></html>", q)
		case "/static_noise":
			// Always outputs 49 (e.g. price $49.00)
			fmt.Fprintf(w, "<html><body>Item price: $49.00 for query %s</body></html>", q)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	targetHost := u.Hostname()

	sc := scope.New([]string{targetHost}, nil)

	client := httpx.New(httpx.Config{
		Scope:   sc,
		Timeout: 10 * time.Second,
	})
	validator := NewValidator(client, sc)

	ctx := context.Background()

	// Test Case A: Genuinely Vulnerable SSTI
	candVuln := &RCECandidate{
		ID:             "cand_vuln",
		Origin:         ts.URL,
		Route:          "/ssti_vuln",
		HTTPMethod:     "GET",
		Category:       CategorySSTI,
		RelevantParams: []string{"q"},
	}

	attVuln, err := validator.ValidateCandidate(ctx, candVuln, ProfileSafeActive, nil, "")
	if err != nil {
		t.Fatalf("validation failed unexpectedly: %v", err)
	}
	t.Logf("attVuln: MarkerFound=%v, ReflectionExcluded=%v, posBody=%q, ctlBody=%q",
		attVuln.MarkerFound, attVuln.ReflectionExcluded, attVuln.PositiveResponseObserved, attVuln.ControlResponseObserved)
	if !attVuln.ExecutionConfirmed {
		t.Errorf("expected execution confirmed on vulnerable SSTI, got false (notes: %s)", attVuln.Notes)
	}
	if candVuln.ValidationStatus != StatusValidated {
		t.Errorf("expected status 'validated', got '%s'", candVuln.ValidationStatus)
	}

	// Test Case B: Reflection Trap (verbatim echo)
	candReflect := &RCECandidate{
		ID:             "cand_reflect",
		Origin:         ts.URL,
		Route:          "/reflection_trap",
		HTTPMethod:     "GET",
		Category:       CategorySSTI,
		RelevantParams: []string{"q"},
	}

	attReflect, err := validator.ValidateCandidate(ctx, candReflect, ProfileSafeActive, nil, "")
	if err != nil {
		t.Fatalf("validation failed unexpectedly: %v", err)
	}
	if attReflect.ExecutionConfirmed {
		t.Errorf("reflection trap must NOT confirm execution")
	}
	if candReflect.ValidationStatus == StatusValidated {
		t.Errorf("reflection trap must not be marked as Validated")
	}

	// Test Case C: Static Noise (always 49)
	candNoise := &RCECandidate{
		ID:             "cand_noise",
		Origin:         ts.URL,
		Route:          "/static_noise",
		HTTPMethod:     "GET",
		Category:       CategorySSTI,
		RelevantParams: []string{"q"},
	}

	attNoise, err := validator.ValidateCandidate(ctx, candNoise, ProfileSafeActive, nil, "")
	if err != nil {
		t.Fatalf("validation failed unexpectedly: %v", err)
	}
	if attNoise.ExecutionConfirmed {
		t.Errorf("static noise must NOT confirm execution")
	}
	if candNoise.ValidationStatus == StatusValidated {
		t.Errorf("static noise must not be marked as Validated")
	}
}

func TestGenerateReport(t *testing.T) {
	candidates := []*RCECandidate{
		{
			ID:               "cand_1",
			Origin:           "https://example.com",
			Route:            "/preview",
			HTTPMethod:       "GET",
			Category:         CategorySSTI,
			FeatureType:      "Template Renderer",
			Hypothesis:       "Dynamic template string evaluated server-side.",
			SuspectedSink:    "Jinja2 Template Engine",
			PriorityScore:    85,
			ValidationStatus: StatusValidated,
			ScoreBreakdown: ScoreBreakdown{
				BaseRisk:     28,
				Explanations: []string{"High base risk for SSTI (+28)"},
			},
			ValidationAttempts: []ValidationAttempt{
				{
					AttemptID:          "att_1",
					Profile:            ProfileSafeActive,
					CorrelationID:      "scoutr-test-1",
					ExecutionConfirmed: true,
					MarkerFound:        true,
					ReflectionExcluded: true,
					Notes:              "Math expression 7*7 produced 49.",
				},
			},
		},
	}

	report := GenerateReport("example.com", "scope.yaml", candidates, nil)
	if !strings.Contains(report, "Scoutr RCE Research and Attack Surface Report") {
		t.Errorf("expected report title in generated report")
	}
	if !strings.Contains(report, "Validated RCE Findings") {
		t.Errorf("expected summary table in generated report")
	}
	if !strings.Contains(report, "Jinja2 Template Engine") {
		t.Errorf("expected sink details in generated report")
	}
}
