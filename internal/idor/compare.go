package idor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/httpx"
)

// AccessBoundary represents the structural isolation level between two test accounts.
type AccessBoundary string

const (
	BoundarySameTenant    AccessBoundary = "same_tenant"
	BoundaryCrossTenant   AccessBoundary = "cross_tenant"
	BoundaryCrossInstance AccessBoundary = "cross_instance"
)

var sensitiveFieldNamesRegex = regexp.MustCompile(`(?i)(balance|salary|ssn|social_security|credit_card|card_num|cvv|bank_account|routing|private_key|secret|token|password|auth|tax_id|ein|national_id|phone|email|address|billing|invoice_amount|financials)`)

// ComparisonResult captures the differential authorization evidence across owner, tester, and anonymous requests.
type ComparisonResult struct {
	ID            string              `json:"id"`
	Candidate     ObjectReference     `json:"candidate"`
	OwnerProfile  auth.ProfileSummary `json:"owner_profile"`
	TesterProfile auth.ProfileSummary `json:"tester_profile"`
	Boundary      AccessBoundary      `json:"boundary"`
	RequestURL    string              `json:"request_url"`
	Method        string              `json:"method"`

	// Owner access result (Principal A)
	OwnerStatus      int    `json:"owner_status"`
	OwnerBodySize    int64  `json:"owner_body_size"`
	OwnerContentType string `json:"owner_content_type"`

	// Tester access result (Principal B)
	TesterStatus      int    `json:"tester_status"`
	TesterBodySize    int64  `json:"tester_body_size"`
	TesterContentType string `json:"tester_content_type"`

	// Anonymous access result (Unauthenticated)
	AnonStatus   int   `json:"anon_status"`
	AnonBodySize int64 `json:"anon_body_size"`

	// Heuristics, boundaries, and field-level evidence
	IsPublicResource         bool              `json:"is_public_resource"`
	IsAuthorizedShare        bool              `json:"is_authorized_share"`
	IsSharedOrSameTenant     bool              `json:"is_shared_or_same_tenant"`
	IsDisclosed              bool              `json:"is_disclosed"`
	ObjectIDMatched          bool              `json:"object_id_matched"`
	UniqueMarkerMatched      bool              `json:"unique_marker_matched"`
	DisclosedSensitiveFields []string          `json:"disclosed_sensitive_fields,omitempty"`
	BodySimilarity           float64           `json:"body_similarity"` // Supporting signal (0.0 to 1.0)
	WasCached                bool              `json:"was_cached"`
	IsCacheDeception         bool              `json:"is_cache_deception"`
	CacheReplayVerified      bool              `json:"cache_replay_verified,omitempty"`
	CacheHeaders             map[string]string `json:"cache_headers,omitempty"`
	Status                   IDORStatus        `json:"status"`
	EvidenceNotes            string            `json:"evidence_notes"`
	RedactedOwnerResponse    string            `json:"redacted_owner_response,omitempty"`
	RedactedTesterResponse   string            `json:"redacted_tester_response,omitempty"`
	Timestamp                time.Time         `json:"timestamp"`
}

// CompareEngine executes safe, read-only GET differential authorization checks.
type CompareEngine struct {
	client *httpx.Client
}

// NewCompareEngine creates an initialized CompareEngine with a scope-enforcing HTTP client.
func NewCompareEngine(client *httpx.Client) *CompareEngine {
	return &CompareEngine{
		client: client,
	}
}

// CompareCandidate performs a differential test for an object reference between owner (User A) and tester (User B).
func (eng *CompareEngine) CompareCandidate(ctx context.Context, ref ObjectReference, userA, userB *auth.Profile) (*ComparisonResult, error) {
	if eng.client == nil {
		return nil, fmt.Errorf("scope-enforcing client required")
	}
	if userA == nil || userB == nil {
		return nil, fmt.Errorf("two authenticated profiles (userA and userB) are required")
	}

	// Verify identities via configured IdentityEndpoints if unverified
	if userA.IdentityEndpoint != "" && userA.IdentityStatus == "unverified" {
		_ = userA.VerifyIdentity(ctx, eng.client)
	}
	if userB.IdentityEndpoint != "" && userB.IdentityStatus == "unverified" {
		_ = userB.VerifyIdentity(ctx, eng.client)
	}

	// Gate: Authentication Isolation - check that profiles use distinct credentials
	if err := auth.CheckDistinctCredentials(userA, userB); err != nil {
		return nil, fmt.Errorf("credential isolation check failed: %w", err)
	}

	// Check for same-user resolution
	if userA.PrincipalLabel == userB.PrincipalLabel || (userA.IdentityStatus == "verified" && userB.IdentityStatus == "verified" && userA.VerifiedID != "" && userA.VerifiedID == userB.VerifiedID) {
		res := &ComparisonResult{
			ID:                   fmt.Sprintf("comp_%x", sha256.Sum256([]byte(ref.ID+userA.PrincipalLabel+userB.PrincipalLabel)))[:16],
			Candidate:            ref,
			OwnerProfile:         userA.RedactedSummary(),
			TesterProfile:        userB.RedactedSummary(),
			Boundary:             BoundarySameTenant,
			IsSharedOrSameTenant: true,
			RequestURL:           ref.TargetURL,
			Method:               "GET",
			Status:               IDORStatusSameUser,
			EvidenceNotes:        "Differential testing aborted: profiles resolve to the same user identity",
			Timestamp:            time.Now(),
		}
		return res, nil
	}

	targetURL := ref.TargetURL
	if targetURL == "" {
		return nil, fmt.Errorf("target URL is empty for candidate %s", ref.ID)
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}

	// Determine boundary identity
	boundary := BoundarySameTenant
	if userA.InstanceLabel != "" && userB.InstanceLabel != "" && userA.InstanceLabel != userB.InstanceLabel {
		boundary = BoundaryCrossInstance
	} else if userA.TenantLabel != "" && userB.TenantLabel != "" && userA.TenantLabel != userB.TenantLabel {
		boundary = BoundaryCrossTenant
	}

	res := &ComparisonResult{
		ID:                   fmt.Sprintf("comp_%x", sha256.Sum256([]byte(ref.ID+userA.PrincipalLabel+userB.PrincipalLabel+string(boundary))))[:16],
		Candidate:            ref,
		OwnerProfile:         userA.RedactedSummary(),
		TesterProfile:        userB.RedactedSummary(),
		Boundary:             boundary,
		IsSharedOrSameTenant: (boundary == BoundarySameTenant),
		RequestURL:           u.String(),
		Method:               "GET", // Strictly read-only GET
		Timestamp:            time.Now(),
	}

	// 1. Owner request (User A)
	ownerResp, ownerBody, err := eng.executeRequest(ctx, u.String(), userA)
	if err != nil {
		res.Status = IDORStatusCandidate
		res.EvidenceNotes = fmt.Sprintf("Owner access failed: %v", err)
		return res, nil
	}
	res.OwnerStatus = ownerResp.StatusCode
	res.OwnerBodySize = int64(len(ownerBody))
	res.OwnerContentType = ownerResp.Header.Get("Content-Type")

	// Verify owner baseline
	if res.OwnerStatus != http.StatusOK {
		res.Status = IDORStatusCandidate
		res.EvidenceNotes = fmt.Sprintf("Owner received HTTP %d (not 200 OK); baseline not established", res.OwnerStatus)
		return res, nil
	}

	// Check if owner session expired
	sessionStatus, _ := auth.DetectSessionStatus(ownerResp, ownerBody)
	if sessionStatus == auth.SessionStatusExpired {
		res.Status = IDORStatusCandidate
		res.EvidenceNotes = "Owner session expired during testing"
		return res, nil
	}

	// 2. Tester request (User B)
	testerResp, testerBody, err := eng.executeRequest(ctx, u.String(), userB)
	if err != nil {
		res.Status = IDORStatusCandidate
		res.EvidenceNotes = fmt.Sprintf("Tester access request error: %v", err)
		return res, nil
	}
	res.TesterStatus = testerResp.StatusCode
	res.TesterBodySize = int64(len(testerBody))
	res.TesterContentType = testerResp.Header.Get("Content-Type")

	// 3. Anonymous request (to check if resource is public)
	anonResp, anonBody, _ := eng.executeRequest(ctx, u.String(), nil)
	if anonResp != nil {
		res.AnonStatus = anonResp.StatusCode
		res.AnonBodySize = int64(len(anonBody))
	}

	// 4. Inspect cache headers
	cacheHeaders, wasCached := inspectCacheHeaders(testerResp)
	res.CacheHeaders = cacheHeaders
	res.WasCached = wasCached

	// 5. Canonicalize bodies for comparison
	canonOwner := CanonicalizeBody(ownerBody, res.OwnerContentType)
	canonTester := CanonicalizeBody(testerBody, res.TesterContentType)
	canonAnon := CanonicalizeBody(anonBody, "")

	// 6. Check if resource is public
	if res.AnonStatus == http.StatusOK && bytes.Equal(canonAnon, canonOwner) && len(canonAnon) > 0 {
		res.IsPublicResource = true
		res.Status = IDORStatusNeedsReview
		res.EvidenceNotes = "Public resource: Anonymous unauthenticated request returned matching 200 OK response"
		return res, nil
	}

	// 7. Check if access is explicitly permitted under expected policy
	if ref.IsExpectedAuthorized(userB.PrincipalLabel, userB.TenantLabel, userB.InstanceLabel, userB.RoleLabel) {
		res.IsAuthorizedShare = true
		res.Status = IDORStatusAuthorizedShare
		res.EvidenceNotes = fmt.Sprintf("Authorized access: User '%s' has valid '%s' access under policy '%s'",
			userB.PrincipalLabel, userB.RoleLabel, ref.AccessPolicy)
		return res, nil
	}

	// Unknown policies cannot be confirmed as IDOR automatically; produce NeedsReview candidate
	if ref.AccessPolicy == AccessPolicyUnknown || ref.AccessPolicy == "unknown" {
		res.Status = IDORStatusNeedsReview
		res.EvidenceNotes = fmt.Sprintf("Access policy is unknown for route %s; manual review required to establish authorization expectations", ref.RouteTemplate)
		return res, nil
	}

	// 8. Evaluate tester access code
	if res.TesterStatus == http.StatusForbidden || res.TesterStatus == http.StatusUnauthorized || res.TesterStatus == http.StatusNotFound {
		res.Status = IDORStatusCandidate
		res.EvidenceNotes = fmt.Sprintf("Access correctly denied: Tester received HTTP %d", res.TesterStatus)
		return res, nil
	}

	// 9. If Tester received 200 OK
	if res.TesterStatus == http.StatusOK {
		// Detect soft 200 login redirect
		testerSessionStatus, _ := auth.DetectSessionStatus(testerResp, testerBody)
		if testerSessionStatus == auth.SessionStatusExpired {
			res.Status = IDORStatusCandidate
			res.EvidenceNotes = "Tester session expired or redirected to login"
			return res, nil
		}

		// Calculate supporting Jaccard similarity
		sim := calculateSimilarity(canonOwner, canonTester)
		res.BodySimilarity = sim

		// Filter out empty responses ([] or {})
		trimmedTester := strings.TrimSpace(string(testerBody))
		if trimmedTester == "[]" || trimmedTester == "{}" || len(testerBody) == 0 {
			res.Status = IDORStatusCandidate
			res.EvidenceNotes = "Tester received empty response collection; unauthorized data was not disclosed"
			return res, nil
		}

		// Field-level canonical JSON comparison
		objMatched, markerMatched, sensitiveFields := analyzeFieldLevelDisclosure(testerBody, ref)
		res.ObjectIDMatched = objMatched
		res.UniqueMarkerMatched = markerMatched
		res.DisclosedSensitiveFields = sensitiveFields

		// Require concrete evidence that protected object data was obtained
		hasDisclosureEvidence := objMatched || markerMatched || len(sensitiveFields) > 0 || sim > 0.85
		if hasDisclosureEvidence {
			res.IsDisclosed = true
			res.RedactedOwnerResponse = truncateString(string(canonOwner), 500)
			res.RedactedTesterResponse = truncateString(string(canonTester), 500)

			// Detect Web Cache Deception vs Direct Authorization Failure
			// Controlled cross-account replay evidence required: cached response containing owner's private object/data
			if wasCached && isCacheDeceptionHeader(cacheHeaders) {
				if objMatched || markerMatched || len(sensitiveFields) > 0 {
					res.IsCacheDeception = true
					res.CacheReplayVerified = true
					res.Status = IDORStatusCacheDeception
					res.EvidenceNotes = fmt.Sprintf("Web Cache Deception confirmed via cross-account replay: Tester received cached response of owner's private object (Age: %s, Cache-Control: %s)",
						cacheHeaders["Age"], cacheHeaders["Cache-Control"])
					return res, nil
				}
			}

			// Check unauthorized role access (Privilege escalation within tenant)
			if boundary == BoundarySameTenant && (ref.AccessPolicy == AccessPolicyRoleRestricted || ref.AccessPolicy == "role_restricted") {
				res.Status = IDORStatusUnauthorizedRole
				res.EvidenceNotes = fmt.Sprintf("Intra-Tenant Unauthorized Role Access (Privilege Escalation): User '%s' (role '%s') accessed restricted object '%s' requiring role(s) %v",
					userB.PrincipalLabel, userB.RoleLabel, ref.ObjectID, ref.AllowedRoles)
				return res, nil
			}

			// Boundary classifications
			switch boundary {
			case BoundaryCrossInstance:
				res.Status = IDORStatusCrossInstance
				res.EvidenceNotes = fmt.Sprintf("CRITICAL Cross-Instance IDOR: Tester in instance '%s' accessed private object '%s' in instance '%s'",
					userB.InstanceLabel, ref.ObjectID, ref.OwnerInstance)
			case BoundaryCrossTenant:
				res.Status = IDORStatusCrossTenant
				res.EvidenceNotes = fmt.Sprintf("HIGH Cross-Tenant IDOR: Tester in tenant '%s' accessed private object '%s' in tenant '%s'",
					userB.TenantLabel, ref.ObjectID, ref.OwnerTenant)
			case BoundarySameTenant:
				res.Status = IDORStatusSameTenantUnauthorized
				res.EvidenceNotes = fmt.Sprintf("Intra-Tenant IDOR: User '%s' accessed private object '%s' owned by '%s' in same tenant '%s' violating policy '%s'",
					userB.PrincipalLabel, ref.ObjectID, ref.OwnerPrincipal, ref.OwnerTenant, ref.AccessPolicy)
			}
			return res, nil
		}

		// Differing content without disclosure evidence
		res.Status = IDORStatusNeedsReview
		res.EvidenceNotes = fmt.Sprintf("Tester received HTTP 200 with differing response body without explicit object data disclosure (similarity: %.2f)", sim)
		return res, nil
	}

	res.Status = IDORStatusNeedsReview
	res.EvidenceNotes = fmt.Sprintf("Inconclusive: Owner HTTP %d, Tester HTTP %d", res.OwnerStatus, res.TesterStatus)
	return res, nil
}

func (eng *CompareEngine) executeRequest(ctx context.Context, targetURL string, profile *auth.Profile) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, nil, err
	}

	if profile != nil {
		profile.ApplyToRequest(req)
	}

	resp, err := eng.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // 512 KB cap
	if err != nil {
		return resp, nil, err
	}

	return resp, body, nil
}

// analyzeFieldLevelDisclosure inspects response JSON for object IDs, unique markers, and sensitive fields.
func analyzeFieldLevelDisclosure(body []byte, ref ObjectReference) (bool, bool, []string) {
	objMatched := false
	markerMatched := false
	var sensitiveFields []string

	if len(body) == 0 {
		return false, false, nil
	}

	// 1. Check unique test marker if specified
	if ref.UniqueMarker != "" && bytes.Contains(body, []byte(ref.UniqueMarker)) {
		markerMatched = true
	}

	// 2. Check if concrete object ID is present
	if ref.ObjectID != "" && bytes.Contains(body, []byte(ref.ObjectID)) {
		objMatched = true
	}

	// 3. Inspect JSON fields
	var m map[string]any
	if err := json.Unmarshal(body, &m); err == nil {
		sensitiveFields = findSensitiveFields(m)
	}

	return objMatched, markerMatched, sensitiveFields
}

func findSensitiveFields(m map[string]any) []string {
	var found []string
	seen := make(map[string]bool)

	var walk func(sub map[string]any, prefix string)
	walk = func(sub map[string]any, prefix string) {
		for k, v := range sub {
			fullName := k
			if prefix != "" {
				fullName = prefix + "." + k
			}
			if sensitiveFieldNamesRegex.MatchString(k) && !seen[fullName] {
				seen[fullName] = true
				found = append(found, fullName)
			}
			if nextMap, ok := v.(map[string]any); ok {
				walk(nextMap, fullName)
			}
		}
	}
	walk(m, "")
	sort.Strings(found)
	return found
}

func inspectCacheHeaders(resp *http.Response) (map[string]string, bool) {
	if resp == nil {
		return nil, false
	}
	cacheHeaders := make(map[string]string)
	checkKeys := []string{"Cache-Control", "Age", "ETag", "X-Cache", "CF-Cache-Status", "Expires", "Vary"}

	wasCached := false
	for _, k := range checkKeys {
		val := resp.Header.Get(k)
		if val != "" {
			cacheHeaders[k] = val
			valLower := strings.ToLower(val)
			if strings.Contains(valLower, "hit") {
				wasCached = true
			}
		}
	}
	if ageVal := resp.Header.Get("Age"); ageVal != "" && ageVal != "0" {
		wasCached = true
	}

	return cacheHeaders, wasCached
}

func isCacheDeceptionHeader(headers map[string]string) bool {
	if headers == nil {
		return false
	}
	cc := strings.ToLower(headers["Cache-Control"])
	// Public cache header or explicit cache hit
	if strings.Contains(cc, "public") || strings.Contains(strings.ToLower(headers["X-Cache"]), "hit") ||
		strings.Contains(strings.ToLower(headers["CF-Cache-Status"]), "hit") {
		return true
	}
	return false
}

// CanonicalizeBody strips volatile dynamic fields (timestamps, csrf tokens, request IDs) from JSON
// and standardizes formatting for reliable differential comparison.
func CanonicalizeBody(body []byte, contentType string) []byte {
	if len(body) == 0 {
		return nil
	}

	// Try JSON canonicalization
	var m map[string]any
	if err := json.Unmarshal(body, &m); err == nil {
		stripVolatileFields(m)
		canon, err := json.Marshal(m)
		if err == nil {
			return canon
		}
	}

	var arr []any
	if err := json.Unmarshal(body, &arr); err == nil {
		canon, err := json.Marshal(arr)
		if err == nil {
			return canon
		}
	}

	// Fallback to normalized whitespace string
	trimmed := bytes.TrimSpace(body)
	return trimmed
}

var volatileFields = map[string]bool{
	"timestamp":  true,
	"time":       true,
	"date":       true,
	"created_at": true,
	"updated_at": true,
	"request_id": true,
	"req_id":     true,
	"trace_id":   true,
	"csrf":       true,
	"nonce":      true,
}

func stripVolatileFields(m map[string]any) {
	for k, v := range m {
		lowerKey := strings.ToLower(k)
		if volatileFields[lowerKey] {
			delete(m, k)
		} else if subMap, ok := v.(map[string]any); ok {
			stripVolatileFields(subMap)
		}
	}
}

// calculateSimilarity returns a basic Jaccard word-set similarity ratio between 0.0 and 1.0.
func calculateSimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	wordsA := tokenize(a)
	wordsB := tokenize(b)

	setA := make(map[string]bool, len(wordsA))
	for _, w := range wordsA {
		setA[w] = true
	}

	intersection := 0
	setUnion := make(map[string]bool, len(wordsA)+len(wordsB))
	for _, w := range wordsA {
		setUnion[w] = true
	}
	for _, w := range wordsB {
		setUnion[w] = true
		if setA[w] {
			intersection++
		}
	}

	if len(setUnion) == 0 {
		return 1.0
	}
	return float64(intersection) / float64(len(setUnion))
}

func tokenize(b []byte) []string {
	fields := strings.FieldsFunc(string(b), func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ',' || r == '{' || r == '}' || r == '[' || r == ']' || r == ':' || r == '"'
	})
	sort.Strings(fields)
	return fields
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[TRUNCATED]"
}
