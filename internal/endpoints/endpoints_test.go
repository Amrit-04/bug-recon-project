package endpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

func TestNormalizeURL(t *testing.T) {
	raw := "https://api.example.com/api/v1/users/1024/documents/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11?token=secret123&account_id=9999#preview"
	canonical, route, params, candidates := NormalizeURL(raw)

	if route != "api.example.com/api/v1/users/{id}/documents/{uuid}" {
		t.Errorf("unexpected normalized route: %s", route)
	}

	if len(params) != 2 || params[0] != "account_id" || params[1] != "token" {
		t.Errorf("unexpected params: %v", params)
	}

	if len(candidates) != 3 { // path id (1024), path uuid, query account_id (9999)
		t.Errorf("expected 3 ID candidates, got %d: %+v", len(candidates), candidates)
	}

	if canonical != "https://api.example.com/api/v1/users/1024/documents/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11?account_id=9999&token=secret123" {
		t.Errorf("unexpected canonical URL: %s", canonical)
	}
}

func TestClassifyEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		route       string
		params      []string
		body        []string
		content     []string
		expectedTag FunctionClassification
	}{
		{
			name:        "File Upload",
			route:       "/api/v1/documents/upload",
			content:     []string{"multipart/form-data"},
			expectedTag: ClassFileProcess,
		},
		{
			name:        "Document Conversion",
			route:       "/tools/html2pdf",
			params:      []string{"format", "source"},
			expectedTag: ClassDocConvert,
		},
		{
			name:        "Template Preview",
			route:       "/emails/template/render",
			expectedTag: ClassTemplateRender,
		},
		{
			name:        "Archive Unpack",
			route:       "/system/backup/unzip",
			expectedTag: ClassArchiveExtract,
		},
		{
			name:        "CSV Export",
			route:       "/reports/export.csv",
			expectedTag: ClassImportExport,
		},
		{
			name:        "Image Resize",
			route:       "/media/thumbnail",
			params:      []string{"width", "height"},
			expectedTag: ClassImageProcess,
		},
		{
			name:        "Background Worker",
			route:       "/queue/jobs/async",
			expectedTag: ClassBackgroundJob,
		},
		{
			name:        "Webhook Event",
			route:       "/api/webhook/github",
			expectedTag: ClassWebhook,
		},
		{
			name:        "CI Pipeline",
			route:       "/ci/pipeline/runner/execute",
			expectedTag: ClassBuildWorkflow,
		},
		{
			name:        "User Data",
			route:       "/api/account/profile",
			expectedTag: ClassUserData,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tags := ClassifyEndpoint(tc.route, tc.params, tc.body, tc.content)
			found := false
			for _, tag := range tags {
				if tag == tc.expectedTag {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected tag %s in %v for route %s", tc.expectedTag, tags, tc.route)
			}
		})
	}
}

func TestInventoryDeduplicationAndProvenance(t *testing.T) {
	inv := NewInventory()

	ep1 := &Endpoint{
		URL:             "https://api.example.com/api/users/1",
		NormalizedRoute: "api.example.com/api/users/{id}",
		Methods:         []string{"GET"},
		QueryParams:     []string{"view"},
		Sources:         []string{"katana"},
		DiscoveredAt:    time.Now(),
	}

	ep2 := &Endpoint{
		URL:             "https://api.example.com/api/users/2",
		NormalizedRoute: "api.example.com/api/users/{id}",
		Methods:         []string{"GET"},
		QueryParams:     []string{"sort"},
		Sources:         []string{"archive"},
		DiscoveredAt:    time.Now(),
	}

	inv.AddOrMerge(ep1)
	inv.AddOrMerge(ep2)

	if inv.Count() != 1 {
		t.Fatalf("expected 1 deduplicated endpoint, got %d", inv.Count())
	}

	all := inv.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 item, got %d", len(all))
	}

	item := all[0]
	// Check merged query params: view, sort
	if len(item.QueryParams) != 2 || item.QueryParams[0] != "sort" || item.QueryParams[1] != "view" {
		t.Errorf("unexpected merged params: %v", item.QueryParams)
	}

	// Check provenance preserved: katana and archive
	if len(item.Sources) != 2 || item.Sources[0] != "archive" || item.Sources[1] != "katana" {
		t.Errorf("unexpected merged sources: %v", item.Sources)
	}

	// Check JSON serialization roundtrip
	jsonData, err := inv.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	inv2 := NewInventory()
	if err := inv2.FromJSON(jsonData); err != nil {
		t.Fatalf("FromJSON error: %v", err)
	}
	if inv2.Count() != 1 {
		t.Errorf("expected 1 after deserialization, got %d", inv2.Count())
	}
}

func TestExtractEndpointsFromJS(t *testing.T) {
	jsCode := `
		function loadUser(id) {
			fetch("/api/v1/users/" + id);
			axios.get('/api/v1/documents/export');
			const logo = "/assets/images/logo.png";
			const css = "/style.css";
			const endpoint = "/admin/system/settings";
		}
	`

	sc := scope.New([]string{"example.com", "*.example.com"}, nil)
	results := ExtractEndpointsFromJS(jsCode, "https://app.example.com/main.js", sc)

	routes := make(map[string]bool)
	for _, ep := range results {
		routes[ep.NormalizedRoute] = true
	}

	if !routes["app.example.com/api/v1/users"] {
		t.Errorf("missing route app.example.com/api/v1/users in %v", routes)
	}
	if !routes["app.example.com/api/v1/documents/export"] {
		t.Errorf("missing route app.example.com/api/v1/documents/export in %v", routes)
	}
	if !routes["app.example.com/admin/system/settings"] {
		t.Errorf("missing route app.example.com/admin/system/settings in %v", routes)
	}
	// Static assets like .png and .css must not be treated as API endpoints
	if routes["app.example.com/assets/images/logo.png"] || routes["app.example.com/style.css"] {
		t.Errorf("static assets incorrectly included: %v", routes)
	}
}

func TestParseOpenAPISpec(t *testing.T) {
	specJSON := []byte(`{
		"openapi": "3.0.0",
		"info": { "title": "Test API", "version": "1.0" },
		"paths": {
			"/api/v1/files/upload": {
				"post": {
					"summary": "Upload file",
					"parameters": [
						{ "name": "category", "in": "query" }
					],
					"requestBody": {
						"content": {
							"multipart/form-data": {
								"schema": {
									"properties": {
										"file": { "type": "string" },
										"description": { "type": "string" }
									}
								}
							}
						}
					},
					"security": [{ "BearerAuth": [] }]
				}
			}
		}
	}`)

	sc := scope.New([]string{"api.example.com"}, nil)
	endpoints, err := ParseOpenAPISpec(specJSON, "https://api.example.com", sc)
	if err != nil {
		t.Fatalf("ParseOpenAPISpec error: %v", err)
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	ep := endpoints[0]
	if ep.NormalizedRoute != "api.example.com/api/v1/files/upload" {
		t.Errorf("unexpected route: %s", ep.NormalizedRoute)
	}
	if len(ep.Methods) != 1 || ep.Methods[0] != "POST" {
		t.Errorf("unexpected methods: %v", ep.Methods)
	}
	if len(ep.QueryParams) != 1 || ep.QueryParams[0] != "category" {
		t.Errorf("unexpected query params: %v", ep.QueryParams)
	}
	if len(ep.BodyFields) != 2 {
		t.Errorf("expected 2 body fields (file, description), got %v", ep.BodyFields)
	}
	if !ep.AuthRequired {
		t.Errorf("expected AuthRequired=true")
	}
}

func TestDiscoverPublicAPISpecWithMockServer(t *testing.T) {
	specJSON := `{
		"swagger": "2.0",
		"basePath": "/api",
		"paths": {
			"/documents": {
				"get": {
					"parameters": [{ "name": "doc_id", "in": "query" }]
				}
			}
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(specJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	sc := scope.New([]string{"127.0.0.1", "localhost"}, nil)
	client := httpx.New(httpx.Config{
		Scope:       sc,
		Timeout:     2 * time.Second,
		MaxBodySize: 1024 * 1024,
		GlobalRate:  50,
		PerHostRate: 50,
	})

	eps, matchedURL := DiscoverPublicAPISpec(context.Background(), client, server.URL, sc)
	if len(eps) != 1 {
		t.Fatalf("expected 1 discovered endpoint from mock server, got %d", len(eps))
	}
	if matchedURL == "" {
		t.Errorf("expected matchedURL to be non-empty")
	}
}
