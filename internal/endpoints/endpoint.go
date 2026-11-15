package endpoints

import (
	"fmt"
	"strings"
	"time"
)

// FunctionClassification tags the suspected business or technical functionality of an endpoint.
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

// ResponseMetadata holds high-level HTTP response characteristics without sensitive response bodies.
type ResponseMetadata struct {
	StatusCode    int               `json:"status_code,omitempty"`
	ContentLength int64             `json:"content_length,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// Endpoint represents a consolidated, normalized API or web endpoint discovered during testing.
type Endpoint struct {
	// Canonical full URL (or base representation)
	URL string `json:"url"`

	// Route template with parameterized identifiers (e.g. "/api/v1/users/{id}/documents/{uuid}")
	NormalizedRoute string `json:"normalized_route"`

	// Allowed / observed HTTP methods (e.g. ["GET", "POST"])
	Methods []string `json:"methods"`

	// Extracted query parameter keys (values stripped for privacy)
	QueryParams []string `json:"query_params,omitempty"`

	// Top-level or nested JSON request body field names (structure only, no sensitive values)
	BodyFields []string `json:"body_fields,omitempty"`

	// Accepted or observed Content-Types (e.g. "application/json", "multipart/form-data")
	ContentTypes []string `json:"content_types,omitempty"`

	// Authentication status
	AuthRequired bool   `json:"auth_required"`
	AuthType     string `json:"auth_type,omitempty"` // "bearer", "cookie", "api_key", "none", "unknown"

	// Technologies identified running on or serving this route
	TechFingerprints []string `json:"tech_fingerprints,omitempty"`

	// Provenance: stages or tools that reported this endpoint (e.g. ["katana", "archive", "js_extract", "openapi_spec"])
	Sources []string `json:"sources"`

	// Functional categorization (e.g. [ClassFileProcess, ClassDocConvert])
	Classifications []FunctionClassification `json:"classifications,omitempty"`

	// Response summary
	ResponseMetadata *ResponseMetadata `json:"response_metadata,omitempty"`

	// Timestamp when first discovered
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Key returns the deterministic deduplication identifier for this endpoint.
// Groups by Method + Host + NormalizedRoute.
func (e *Endpoint) Key(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	return fmt.Sprintf("%s:%s", method, e.NormalizedRoute)
}
