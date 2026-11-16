package rce

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

// SafeCheck defines a paired benign probe and negative control for safe marker-based validation.
type SafeCheck struct {
	Name           string
	Category       RCECategory
	PositiveProbe  string // Benign math evaluation (e.g. "${7*7}")
	PositiveMarker string // Expected calculated result (e.g. "49")
	ControlProbe   string // Control math evaluation (e.g. "${7*8}")
	ControlMarker  string // Expected control result (e.g. "56")
	NeutralControl string // Plain text without expression markers (e.g. "scoutr_static_test")
}

// Default safe validation test probes
var defaultSafeChecks = map[RCECategory][]SafeCheck{
	CategorySSTI: {
		{
			Name:           "Jinja2 / Twig / Smarty Curly Marker Check",
			Category:       CategorySSTI,
			PositiveProbe:  "{{7*7}}",
			PositiveMarker: "49",
			ControlProbe:   "{{7*8}}",
			ControlMarker:  "56",
			NeutralControl: "scoutr_safe_marker",
		},
		{
			Name:           "Thymeleaf / Freemarker Bracket Marker Check",
			Category:       CategorySSTI,
			PositiveProbe:  "${7*7}",
			PositiveMarker: "49",
			ControlProbe:   "${7*8}",
			ControlMarker:  "56",
			NeutralControl: "scoutr_safe_marker",
		},
	},
	CategoryExpressionLanguage: {
		{
			Name:           "SpEL / OGNL Expression Math Check",
			Category:       CategoryExpressionLanguage,
			PositiveProbe:  "${7*7}",
			PositiveMarker: "49",
			ControlProbe:   "${7*8}",
			ControlMarker:  "56",
			NeutralControl: "scoutr_safe_marker",
		},
		{
			Name:           "Ruby / Elixir String Interpolation Check",
			Category:       CategoryExpressionLanguage,
			PositiveProbe:  "#{7*7}",
			PositiveMarker: "49",
			ControlProbe:   "#{7*8}",
			ControlMarker:  "56",
			NeutralControl: "scoutr_safe_marker",
		},
	},
	CategoryCommandInjection: {
		{
			Name:           "Subshell Arithmetic Expansion Check",
			Category:       CategoryCommandInjection,
			PositiveProbe:  "$(expr 7 '*' 7)",
			PositiveMarker: "49",
			ControlProbe:   "$(expr 7 '*' 8)",
			ControlMarker:  "56",
			NeutralControl: "127.0.0.1",
		},
		{
			Name:           "Backtick Shell Arithmetic Check",
			Category:       CategoryCommandInjection,
			PositiveProbe:  "`expr 7 '*' 7`",
			PositiveMarker: "49",
			ControlProbe:   "`expr 7 '*' 8`",
			ControlMarker:  "56",
			NeutralControl: "127.0.0.1",
		},
	},
}

// Validator executes graduated, scope-guarded RCE validation.
type Validator struct {
	client       *httpx.Client
	scopeChecker *scope.Scope
}

// NewValidator initializes a Validator with a scope-guarded HTTP client.
func NewValidator(client *httpx.Client, sc *scope.Scope) *Validator {
	return &Validator{
		client:       client,
		scopeChecker: sc,
	}
}

// ValidateCandidate executes validation according to the selected profile.
func (v *Validator) ValidateCandidate(
	ctx context.Context,
	cand *RCECandidate,
	profile ValidationProfile,
	authProfile *auth.Profile,
	callbackURL string,
) (*ValidationAttempt, error) {
	switch profile {
	case ProfilePassive:
		return v.validatePassive(cand)
	case ProfileSafeActive:
		return v.validateSafeActive(ctx, cand, authProfile, callbackURL)
	case ProfileManual:
		return v.generateManualVerificationPlan(cand, authProfile)
	default:
		return nil, fmt.Errorf("unrecognized validation profile: %s", profile)
	}
}

// Profile 1: Passive Research — zero target network requests
func (v *Validator) validatePassive(cand *RCECandidate) (*ValidationAttempt, error) {
	now := time.Now()
	corrID := generateCorrelationID()

	notes := "Passive research completed. Evaluated endpoint inventory, technology fingerprints, and public advisories without network requests."
	status := cand.ValidationStatus

	if len(cand.MatchingAdvisories) > 0 {
		for _, m := range cand.MatchingAdvisories {
			if m.ProgressionTier == TierComponentReachable || m.ProgressionTier == TierComponentCorroborated {
				status = StatusCorroborated
				notes += fmt.Sprintf(" Corroborated by advisory %s (%s).", m.Advisory.ID, m.ProgressionTier)
				break
			}
		}
	}

	cand.ValidationStatus = status
	cand.UpdatedAt = now

	attempt := &ValidationAttempt{
		AttemptID:          fmt.Sprintf("att_passive_%s", corrID[:8]),
		Profile:            ProfilePassive,
		Timestamp:          now,
		CorrelationID:      corrID,
		ExecutionConfirmed: false,
		Notes:              notes,
	}

	cand.LastAttempt = attempt
	cand.ValidationAttempts = append(cand.ValidationAttempts, *attempt)
	return attempt, nil
}

// Profile 2: Safe Active Research — harmless marker-based evaluation checks with controls
func (v *Validator) validateSafeActive(
	ctx context.Context,
	cand *RCECandidate,
	authProfile *auth.Profile,
	callbackURL string,
) (*ValidationAttempt, error) {
	now := time.Now()
	corrID := generateCorrelationID()

	// 1. Scope Verification
	targetHost := extractHost(cand.Origin)
	if v.scopeChecker != nil && !v.scopeChecker.IsInScope(targetHost) {
		return nil, fmt.Errorf("target host '%s' is strictly out of configured scope", targetHost)
	}

	// Determine parameter to test
	param := ""
	if len(cand.RelevantParams) > 0 {
		param = cand.RelevantParams[0]
	} else if len(cand.RelevantBodyFields) > 0 {
		param = cand.RelevantBodyFields[0]
	} else {
		param = "q"
	}

	// Select appropriate safe check probes for this category
	checks, ok := defaultSafeChecks[cand.Category]
	if !ok || len(checks) == 0 {
		// Fallback safe expression check
		checks = defaultSafeChecks[CategoryExpressionLanguage]
	}
	check := checks[0]

	// 2. Execute Neutral Control Baseline Request
	neutralReq, neutralBody, err := v.executeProbe(ctx, cand, authProfile, param, check.NeutralControl, corrID)
	if err != nil {
		return nil, fmt.Errorf("control baseline request failed: %w", err)
	}

	// Check if the neutral string already contained the positive marker (would be false positive)
	if strings.Contains(neutralBody, check.PositiveMarker) {
		attempt := &ValidationAttempt{
			AttemptID:               fmt.Sprintf("att_active_%s", corrID[:8]),
			Profile:                 ProfileSafeActive,
			Timestamp:               now,
			Parameter:               param,
			CorrelationID:           corrID,
			ControlRequestSent:      neutralReq,
			ControlResponseObserved: truncateSnippet(neutralBody, 300),
			Notes:                   fmt.Sprintf("False-positive control: target naturally reflects marker '%s' in ordinary responses. Rejected.", check.PositiveMarker),
			ExecutionConfirmed:      false,
			MarkerFound:             false,
		}
		cand.ValidationStatus = StatusNeedsManualReview
		cand.ValidationAttempts = append(cand.ValidationAttempts, *attempt)
		return attempt, nil
	}

	// 3. Execute Positive Probe Request (e.g. {{7*7}})
	posReq, posBody, err := v.executeProbe(ctx, cand, authProfile, param, check.PositiveProbe, corrID)
	if err != nil {
		return nil, fmt.Errorf("positive probe request failed: %w", err)
	}

	// Strict Reflection Check: Did the response simply echo the payload verbatim?
	reflectionDetected := strings.Contains(posBody, check.PositiveProbe)

	// Marker Check: Did the calculated result (e.g. 49) appear?
	markerFound := strings.Contains(posBody, check.PositiveMarker)

	// 4. Execute Negative Control Request (e.g. {{7*8}} -> 56)
	ctlReq, ctlBody, err := v.executeProbe(ctx, cand, authProfile, param, check.ControlProbe, corrID)
	if err != nil {
		return nil, fmt.Errorf("negative control request failed: %w", err)
	}

	controlMarkerFound := strings.Contains(ctlBody, check.ControlMarker)

	// Deterministic Gate Requirements:
	// - Marker was found in positive probe response (e.g. 49)
	// - Control marker was found in negative control response (e.g. 56)
	// - Literal payload was NOT echoed verbatim (or if echoed, calculated result was separately produced)
	executionConfirmed := markerFound && controlMarkerFound && !reflectionDetected

	notes := ""
	if executionConfirmed {
		cand.ValidationStatus = StatusValidated
		notes = fmt.Sprintf("Confirmed server-side expression evaluation! Mathematical probe '%s' evaluated to '%s' and control probe '%s' evaluated to '%s'. Raw payload was not echoed.",
			check.PositiveProbe, check.PositiveMarker, check.ControlProbe, check.ControlMarker)
	} else if markerFound && reflectionDetected {
		cand.ValidationStatus = StatusNeedsManualReview
		notes = fmt.Sprintf("Marker '%s' observed but payload '%s' was echoed verbatim. Appears to be reflected user input, NOT server-side execution.",
			check.PositiveMarker, check.PositiveProbe)
	} else {
		cand.ValidationStatus = StatusNeedsManualReview
		notes = fmt.Sprintf("Safe probes did not produce dynamic calculation markers. Requires manual review or custom application parameters.")
	}

	cand.UpdatedAt = now
	attempt := &ValidationAttempt{
		AttemptID:                fmt.Sprintf("att_active_%s", corrID[:8]),
		Profile:                  ProfileSafeActive,
		Timestamp:                now,
		Parameter:                param,
		CorrelationID:            corrID,
		ControlRequestSent:       ctlReq,
		ControlResponseObserved:  truncateSnippet(ctlBody, 400),
		PositiveRequestSent:      posReq,
		PositiveResponseObserved: truncateSnippet(posBody, 400),
		MarkerExpected:           check.PositiveMarker,
		MarkerFound:              markerFound,
		ReflectionExcluded:       !reflectionDetected,
		ExecutionConfirmed:       executionConfirmed,
		Notes:                    notes,
	}

	cand.LastAttempt = attempt
	cand.ValidationAttempts = append(cand.ValidationAttempts, *attempt)
	return attempt, nil
}

// Profile 3: Manual Verification — prepares reproducible curl command and review notes
func (v *Validator) generateManualVerificationPlan(cand *RCECandidate, authProfile *auth.Profile) (*ValidationAttempt, error) {
	now := time.Now()
	corrID := generateCorrelationID()

	reqURL := cand.Origin + cand.Route
	curlCmd := fmt.Sprintf("curl -i -s -k -X %s '%s'", cand.HTTPMethod, reqURL)

	if authProfile != nil {
		for k, val := range authProfile.Headers {
			curlCmd += fmt.Sprintf(" -H '%s: %s'", k, val)
		}
		if len(authProfile.Cookies) > 0 {
			var parts []string
			for _, c := range authProfile.Cookies {
				parts = append(parts, c.String())
			}
			curlCmd += fmt.Sprintf(" -H 'Cookie: %s'", strings.Join(parts, "; "))
		}
	}
	curlCmd += fmt.Sprintf(" -H 'X-Scoutr-Correlate: %s'", corrID)

	cand.ValidationStatus = StatusNeedsManualReview
	cand.UpdatedAt = now

	attempt := &ValidationAttempt{
		AttemptID:           fmt.Sprintf("att_manual_%s", corrID[:8]),
		Profile:             ProfileManual,
		Timestamp:           now,
		CorrelationID:       corrID,
		PositiveRequestSent: curlCmd,
		Notes:               fmt.Sprintf("Manual verification plan prepared. Target: %s (%s). Requires explicit researcher investigation.", cand.Route, cand.Category),
		ExecutionConfirmed:  false,
	}

	cand.LastAttempt = attempt
	cand.ValidationAttempts = append(cand.ValidationAttempts, *attempt)
	return attempt, nil
}

func (v *Validator) executeProbe(
	ctx context.Context,
	cand *RCECandidate,
	authProfile *auth.Profile,
	param string,
	probeVal string,
	corrID string,
) (string, string, error) {
	baseURL := cand.Origin + cand.Route

	var req *http.Request
	var err error
	var recordedReq strings.Builder

	if cand.HTTPMethod == "POST" || cand.HTTPMethod == "PUT" {
		form := url.Values{}
		form.Set(param, probeVal)
		bodyBytes := []byte(form.Encode())

		req, err = http.NewRequestWithContext(ctx, cand.HTTPMethod, baseURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recordedReq.WriteString(fmt.Sprintf("%s %s HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n", cand.HTTPMethod, baseURL))
		recordedReq.WriteString(fmt.Sprintf("\n%s=%s", param, probeVal))
	} else {
		u, parseErr := url.Parse(baseURL)
		if parseErr != nil {
			return "", "", parseErr
		}
		q := u.Query()
		q.Set(param, probeVal)
		u.RawQuery = q.Encode()

		req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		if err != nil {
			return "", "", err
		}
		recordedReq.WriteString(fmt.Sprintf("GET %s HTTP/1.1\n", u.String()))
	}

	req.Header.Set("User-Agent", "Scoutr-Security-Research/1.0")
	req.Header.Set("X-Scoutr-Correlate", corrID)

	// Inject authentication if provided
	if authProfile != nil {
		authProfile.ApplyToRequest(req)
	}

	// Send through scope-enforcing client
	resp, err := v.client.Do(req)
	if err != nil {
		return recordedReq.String(), "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return recordedReq.String(), "", err
	}

	return recordedReq.String(), string(body), nil
}

func generateCorrelationID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "scoutr-" + hex.EncodeToString(b)
}

func extractHost(origin string) string {
	u, err := url.Parse(origin)
	if err == nil && u.Host != "" {
		h := u.Host
		if idx := strings.Index(h, ":"); idx != -1 {
			return h[:idx]
		}
		return h
	}
	return origin
}

func truncateSnippet(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "... [truncated]"
	}
	return s
}
