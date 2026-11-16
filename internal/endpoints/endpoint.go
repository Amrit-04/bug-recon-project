package endpoints

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// FunctionClassification tags the suspected business or technical functionality of an endpoint.
// IMPORTANT: Functional classification indicates suspected attack surface for scoping research.
// It is strictly non-authoritative and does NOT represent an identified vulnerability or confirmed exploitability.
type FunctionClassification string

const (
	ClassFileProcess    FunctionClassification = "file_process"
	ClassDocConvert     FunctionClassification = "doc_convert"
	ClassTemplateRender FunctionClassification = "template_render"
	ClassArchiveExtract FunctionClassification = "archive_extract"
	ClassImportExport   FunctionClassification = "import_export"
	ClassImageProcess   FunctionClassification = "image_process"
	ClassBackgroundJob  FunctionClassification = "background_job"
	ClassWebhook        FunctionClassification = "webhook"
	ClassBuildWorkflow  FunctionClassification = "build_workflow"
	ClassUserData       FunctionClassification = "user_data"
	ClassAdmin          FunctionClassification = "admin"
	ClassAuth           FunctionClassification = "auth"
	ClassGeneralAPI     FunctionClassification = "general_api"
)

// ClassificationConfidence rates the certainty of an endpoint classification based on evidence signals.
type ClassificationConfidence string

const (
	ConfidenceHigh   ClassificationConfidence = "high"
	ConfidenceMedium ClassificationConfidence = "medium"
	ConfidenceLow    ClassificationConfidence = "low"
)

// ClassificationResult records a functional classification along with its confidence, supporting evidence signals,
// and initial research priority.
type ClassificationResult struct {
	Category        FunctionClassification   `json:"category"`
	Confidence      ClassificationConfidence `json:"confidence"`
	EvidenceSignals []string                 `json:"evidence_signals"`
	Priority        int                      `json:"priority"` // 1 (lowest) to 10 (highest research priority)
}

// AuthStatus defines explicit observation states for endpoint authentication.
type AuthStatus string

const (
	AuthStatusAnonymous     AuthStatus = "anonymous"
	AuthStatusAuthenticated AuthStatus = "authenticated"
	AuthStatusUnknown       AuthStatus = "unknown"
	AuthStatusExpired       AuthStatus = "expired"
)

// AuthObservation records an authenticated or anonymous access observation without persisting raw credentials.
// Principal and Tenant labels (e.g. "user_alice", "tenant_a") are tracked for cross-account testing.
type AuthObservation struct {
	Status         AuthStatus `json:"status"`                    // anonymous, authenticated, unknown, expired
	PrincipalLabel string     `json:"principal_label,omitempty"` // label only, NEVER raw credentials or tokens!
	TenantLabel    string     `json:"tenant_label,omitempty"`    // tenant/organization label
	InstanceLabel  string     `json:"instance_label,omitempty"`  // deployment instance / shard label
	RoleLabel      string     `json:"role_label,omitempty"`      // user role within tenant (e.g. "admin", "member")
	AuthType       string     `json:"auth_type,omitempty"`       // "bearer", "cookie", "session", "api_key", "none"
	ObservedAt     time.Time  `json:"observed_at,omitempty"`
	Source         string     `json:"source,omitempty"`
}

// ResponseMetadata holds high-level HTTP response characteristics without sensitive response bodies.
type ResponseMetadata struct {
	StatusCode    int               `json:"status_code,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// Endpoint represents a consolidated, normalized API or web endpoint discovered during testing.
type Endpoint struct {
	// Canonical origin: scheme://host[:port], e.g. "https://api.example.com:8443"
	Origin string `json:"origin"`

	// Canonical full URL (or base representation)
	URL string `json:"url"`

	// Route template with parameterized identifiers (e.g. "/api/v1/users/{id}/documents/{uuid}")
	NormalizedRoute string `json:"normalized_route"`

	// Allowed / observed HTTP methods (e.g. ["GET", "POST"])
	Methods []string `json:"methods"`

	// Concrete URLs observed matching this route template (deduplicated, capped)
	ObservedURLs []string `json:"observed_urls,omitempty"`

	// Concrete object identifiers extracted from URLs, queries, and bodies
	ObservedObjects []ObjectIDCandidate `json:"observed_objects,omitempty"`

	// Extracted query parameter keys (values stripped for privacy)
	QueryParams []string `json:"query_params,omitempty"`

	// Top-level or nested JSON request body field names (structure only, no sensitive values)
	BodyFields []string `json:"body_fields,omitempty"`

	// Accepted or observed Content-Types (e.g. "application/json", "multipart/form-data")
	ContentTypes []string `json:"content_types,omitempty"`

	// Explicit authentication observations from distinct sessions, principals, or tenants
	AuthObservations []AuthObservation `json:"auth_observations,omitempty"`

	// Legacy / high-level authentication status
	AuthRequired bool   `json:"auth_required"`
	AuthType     string `json:"auth_type,omitempty"` // "bearer", "cookie", "api_key", "none", "unknown"

	// Technologies identified running on or serving this route
	TechFingerprints []string `json:"tech_fingerprints,omitempty"`

	// Provenance: stages or tools that reported this endpoint (e.g. ["katana", "archive", "js_extract", "openapi_spec"])
	Sources []string `json:"sources"`

	// Functional categorization with confidence and evidence signals
	Classifications []ClassificationResult `json:"classifications,omitempty"`

	// Response summary
	ResponseMetadata *ResponseMetadata `json:"response_metadata,omitempty"`

	// Timestamp when first discovered
	DiscoveredAt time.Time `json:"discovered_at"`

	mu sync.Mutex `json:"-"`
}

// Key returns the deterministic deduplication identifier for this endpoint.
// Uniquely identifies by HTTP Method + Origin (scheme://host:port) + NormalizedRoute.
func (e *Endpoint) Key(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	origin := strings.TrimRight(strings.ToLower(strings.TrimSpace(e.Origin)), "/")
	if origin == "" && e.URL != "" {
		origin = ExtractOrigin(e.URL)
	}

	route := strings.TrimSpace(e.NormalizedRoute)
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}

	return fmt.Sprintf("%s %s%s", method, origin, route)
}

// ExtractOrigin returns the canonical scheme://host[:port] from a raw URL.
func ExtractOrigin(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, strings.ToLower(u.Host))
}

// AddAuthObservation records an authentication observation, preventing duplicates and ensuring no secrets leak.
func (e *Endpoint) AddAuthObservation(obs AuthObservation) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Normalize labels
	obs.PrincipalLabel = strings.TrimSpace(obs.PrincipalLabel)
	obs.TenantLabel = strings.TrimSpace(obs.TenantLabel)
	obs.AuthType = strings.ToLower(strings.TrimSpace(obs.AuthType))
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now()
	}

	// Update legacy fields
	if obs.Status == AuthStatusAuthenticated {
		e.AuthRequired = true
		if obs.AuthType != "" {
			e.AuthType = obs.AuthType
		}
	}

	// Deduplicate
	for _, existing := range e.AuthObservations {
		if existing.Status == obs.Status &&
			existing.PrincipalLabel == obs.PrincipalLabel &&
			existing.TenantLabel == obs.TenantLabel &&
			existing.AuthType == obs.AuthType {
			return
		}
	}
	e.AuthObservations = append(e.AuthObservations, obs)
}

// AddObservedURL adds a concrete URL observation, deduplicating and capping at maxObservedURLs.
func (e *Endpoint) AddObservedURL(rawURL string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return
	}
	for _, existing := range e.ObservedURLs {
		if existing == rawURL {
			return
		}
	}
	const maxObservedURLs = 50
	if len(e.ObservedURLs) < maxObservedURLs {
		e.ObservedURLs = append(e.ObservedURLs, rawURL)
	}
}

// AddObservedObject adds an object identifier candidate, deduplicating by Type + Name + Value.
func (e *Endpoint) AddObservedObject(obj ObjectIDCandidate) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if obj.Value == "" {
		return
	}
	for _, existing := range e.ObservedObjects {
		if existing.Type == obj.Type && existing.Name == obj.Name && existing.Value == obj.Value {
			return
		}
	}
	const maxObservedObjects = 100
	if len(e.ObservedObjects) < maxObservedObjects {
		e.ObservedObjects = append(e.ObservedObjects, obj)
	}
}
