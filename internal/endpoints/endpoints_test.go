package endpoints

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

func TestNormalizeURL(t *testing.T) {
	raw := "https://api.example.com/api/v1/users/1024/documents/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11?token=secret123&account_id=9999#preview"
	origin, canonical, route, params, candidates := NormalizeURL(raw)

	if origin != "https://api.example.com" {
		t.Errorf("unexpected origin: %s", origin)
	}

	if route != "/api/v1/users/{id}/documents/{uuid}" {
		t.Errorf("unexpected normalized route: %s", route)
	}

	if len(params) != 2 || params[0] != "account_id" || params[1] != "token" {
		t.Errorf("unexpected params: %v", params)
	}

	// Token must be blocked by sensitiveParamRegex, so only:
	// path id (1024), path uuid (a0eebc99-...), and query account_id (9999)
	if len(candidates) != 3 {
		t.Fatalf("expected 3 ID candidates, got %d: %+v", len(candidates), candidates)
	}

	for _, c := range candidates {
		if c.Name == "token" || c.Value == "secret123" {
			t.Errorf("sensitive credential leaked into candidates: %+v", c)
		}
	}

	if canonical != "https://api.example.com/api/v1/users/1024/documents/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11?account_id=9999&token=secret123" {
		t.Errorf("unexpected canonical URL: %s", canonical)
	}
}

func TestClassifyEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		route        string
		params       []string
		body         []string
		content      []string
		expectedTag  FunctionClassification
		expectedConf ClassificationConfidence
		minPrio      int
	}{
		{
			name:         "File Upload (Multi-signal)",
			route:        "/api/v1/documents/upload",
			content:      []string{"multipart/form-data"},
			expectedTag:  ClassFileProcess,
			expectedConf: ConfidenceHigh,
			minPrio:      9,
		},
		{
			name:         "Document Conversion",
			route:        "/tools/html2pdf",
			params:       []string{"format", "source"},
			expectedTag:  ClassDocConvert,
			expectedConf: ConfidenceHigh,
			minPrio:      9,
		},
		{
			name:         "Template Preview",
			route:        "/emails/template/render",
			expectedTag:  ClassTemplateRender,
			expectedConf: ConfidenceMedium,
			minPrio:      9,
		},
		{
			name:         "Archive Unpack",
			route:        "/system/backup/unzip",
			expectedTag:  ClassArchiveExtract,
			expectedConf: ConfidenceMedium,
			minPrio:      9,
		},
		{
			name:         "CSV Export",
			route:        "/reports/export.csv",
			expectedTag:  ClassImportExport,
			expectedConf: ConfidenceMedium,
			minPrio:      7,
		},
		{
			name:         "Image Resize",
			route:        "/media/thumbnail",
			params:       []string{"width", "height"},
			expectedTag:  ClassImageProcess,
			expectedConf: ConfidenceHigh,
			minPrio:      6,
		},
		{
			name:         "Background Worker",
			route:        "/queue/jobs/async",
			expectedTag:  ClassBackgroundJob,
			expectedConf: ConfidenceMedium,
			minPrio:      6,
		},
		{
			name:         "Webhook Event",
			route:        "/api/webhook/github",
			expectedTag:  ClassWebhook,
			expectedConf: ConfidenceMedium,
			minPrio:      5,
		},
		{
			name:         "CI Pipeline",
			route:        "/ci/pipeline/runner/execute",
			expectedTag:  ClassBuildWorkflow,
			expectedConf: ConfidenceMedium,
			minPrio:      10,
		},
		{
			name:         "User Data",
			route:        "/api/account/profile",
			expectedTag:  ClassUserData,
			expectedConf: ConfidenceMedium,
			minPrio:      8,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := ClassifyEndpoint(tc.route, tc.params, tc.body, tc.content)
			var matched *ClassificationResult
			for _, r := range results {
				if r.Category == tc.expectedTag {
					matched = &r
					break
				}
			}
			if matched == nil {
				t.Fatalf("expected tag %s not found in results: %+v", tc.expectedTag, results)
			}
			if matched.Confidence != tc.expectedConf {
				t.Errorf("expected confidence %s, got %s", tc.expectedConf, matched.Confidence)
			}
			if matched.Priority < tc.minPrio {
				t.Errorf("expected priority >= %d, got %d", tc.minPrio, matched.Priority)
			}
			if len(matched.EvidenceSignals) == 0 {
				t.Errorf("expected evidence signals, got empty")
			}
		})
	}
}

// Regression Scenario 1: Identical routes on different domains must not be merged
func TestRegression1_IdenticalRoutesDifferentDomains(t *testing.T) {
	inv := NewInventory()

	inv.AddRawURL("https://api1.example.com/api/v1/users/42", "GET", "katana", nil)
	inv.AddRawURL("https://api2.example.com/api/v1/users/42", "GET", "katana", nil)

	if inv.Count() != 2 {
		t.Fatalf("expected 2 distinct endpoints across different domains, got %d", inv.Count())
	}

	all := inv.GetAll()
	if all[0].Origin == all[1].Origin {
		t.Errorf("expected different origins, got both %s", all[0].Origin)
	}
}

// Regression Scenario 2: Identical routes on different ports must not be merged
func TestRegression2_IdenticalRoutesDifferentPorts(t *testing.T) {
	inv := NewInventory()

	inv.AddRawURL("https://api.example.com:8443/api/v1/status", "GET", "katana", nil)
	inv.AddRawURL("https://api.example.com/api/v1/status", "GET", "katana", nil)

	if inv.Count() != 2 {
		t.Fatalf("expected 2 distinct endpoints across different ports, got %d", inv.Count())
	}

	all := inv.GetAll()
	if all[0].Origin == all[1].Origin {
		t.Errorf("expected different ports in origins, got both %s", all[0].Origin)
	}
}

// Regression Scenario 3: Different authenticated principals preserved separately
func TestRegression3_DifferentAuthenticatedPrincipals(t *testing.T) {
	inv := NewInventory()

	ep := &Endpoint{
		Origin:          "https://app.example.com",
		URL:             "https://app.example.com/api/me",
		NormalizedRoute: "/api/me",
		Methods:         []string{"GET"},
		Sources:         []string{"session_test"},
	}

	ep.AddAuthObservation(AuthObservation{
		Status:         AuthStatusAuthenticated,
		PrincipalLabel: "user_alice",
		TenantLabel:    "tenant_main",
		AuthType:       "cookie",
	})
	inv.AddOrMerge(ep)

	// Second observation from principal user_bob
	ep2 := &Endpoint{
		Origin:          "https://app.example.com",
		URL:             "https://app.example.com/api/me",
		NormalizedRoute: "/api/me",
		Methods:         []string{"GET"},
		Sources:         []string{"session_test"},
	}
	ep2.AddAuthObservation(AuthObservation{
		Status:         AuthStatusAuthenticated,
		PrincipalLabel: "user_bob",
		TenantLabel:    "tenant_main",
		AuthType:       "bearer",
	})
	inv.AddOrMerge(ep2)

	all := inv.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 consolidated endpoint, got %d", len(all))
	}

	endpoint := all[0]
	if len(endpoint.AuthObservations) != 2 {
		t.Fatalf("expected 2 separate principal observations preserved, got %d", len(endpoint.AuthObservations))
	}

	principals := map[string]bool{}
	for _, obs := range endpoint.AuthObservations {
		principals[obs.PrincipalLabel] = true
	}
	if !principals["user_alice"] || !principals["user_bob"] {
		t.Errorf("missing principal in observations: %v", principals)
	}
}

// Regression Scenario 4: Different tenants and instances preserved separately
func TestRegression4_DifferentTenantsAndInstances(t *testing.T) {
	inv := NewInventory()

	ep1 := &Endpoint{
		Origin:          "https://saas.example.com",
		URL:             "https://saas.example.com/api/settings",
		NormalizedRoute: "/api/settings",
		Methods:         []string{"GET"},
	}
	ep1.AddAuthObservation(AuthObservation{
		Status:         AuthStatusAuthenticated,
		PrincipalLabel: "tenant_admin",
		TenantLabel:    "tenant_alpha",
		AuthType:       "bearer",
	})

	ep2 := &Endpoint{
		Origin:          "https://saas.example.com",
		URL:             "https://saas.example.com/api/settings",
		NormalizedRoute: "/api/settings",
		Methods:         []string{"GET"},
	}
	ep2.AddAuthObservation(AuthObservation{
		Status:         AuthStatusAuthenticated,
		PrincipalLabel: "tenant_admin",
		TenantLabel:    "tenant_beta",
		AuthType:       "bearer",
	})

	inv.AddOrMerge(ep1)
	inv.AddOrMerge(ep2)

	all := inv.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(all))
	}

	if len(all[0].AuthObservations) != 2 {
		t.Fatalf("expected 2 distinct tenant observations, got %d", len(all[0].AuthObservations))
	}

	tenants := map[string]bool{}
	for _, obs := range all[0].AuthObservations {
		tenants[obs.TenantLabel] = true
	}
	if !tenants["tenant_alpha"] || !tenants["tenant_beta"] {
		t.Errorf("missing tenant observation: %v", tenants)
	}
}

// Regression Scenario 5: Multiple object IDs sharing a route template preserved
func TestRegression5_MultipleObjectIDsSharingRoute(t *testing.T) {
	inv := NewInventory()

	inv.AddRawURL("https://api.example.com/docs/1", "GET", "crawl", nil)
	inv.AddRawURL("https://api.example.com/docs/2", "GET", "crawl", nil)
	inv.AddRawURL("https://api.example.com/docs/3", "GET", "crawl", nil)

	if inv.Count() != 1 {
		t.Fatalf("expected 1 normalized route for /docs/{id}, got %d", inv.Count())
	}

	all := inv.GetAll()
	ep := all[0]

	if ep.NormalizedRoute != "/docs/{id}" {
		t.Errorf("unexpected normalized route: %s", ep.NormalizedRoute)
	}

	if len(ep.ObservedURLs) != 3 {
		t.Errorf("expected 3 observed URLs, got %d: %v", len(ep.ObservedURLs), ep.ObservedURLs)
	}

	if len(ep.ObservedObjects) != 3 {
		t.Fatalf("expected 3 observed object candidates, got %d: %+v", len(ep.ObservedObjects), ep.ObservedObjects)
	}

	vals := map[string]bool{}
	for _, obj := range ep.ObservedObjects {
		vals[obj.Value] = true
	}
	if !vals["1"] || !vals["2"] || !vals["3"] {
		t.Errorf("missing expected object ID values in %v", vals)
	}
}

// Regression Scenario 6: Different query parameter sets merged cleanly
func TestRegression6_DifferentQueryParameterSets(t *testing.T) {
	inv := NewInventory()

	inv.AddRawURL("https://api.example.com/search?q=gopher&limit=25", "GET", "source1", nil)
	inv.AddRawURL("https://api.example.com/search?sort=desc&page=2", "GET", "source2", nil)

	all := inv.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(all))
	}

	params := all[0].QueryParams
	expected := []string{"limit", "page", "q", "sort"}
	if len(params) != len(expected) {
		t.Fatalf("expected 4 query params, got %d: %v", len(params), params)
	}
	for i, exp := range expected {
		if params[i] != exp {
			t.Errorf("param[%d] expected %s, got %s", i, exp, params[i])
		}
	}
}

// Regression Scenario 7: Out-of-scope OpenAPI servers must be dropped
func TestRegression7_OutOfScopeOpenAPIServers(t *testing.T) {
	specJSON := []byte(`{
		"openapi": "3.0.0",
		"info": { "title": "Test", "version": "1.0" },
		"servers": [
			{ "url": "https://inscope.example.com/v1" },
			{ "url": "https://evil-external.com/v1" }
		],
		"paths": {
			"/data": {
				"get": { "summary": "Get data" }
			}
		}
	}`)

	sc := scope.New([]string{"inscope.example.com"}, nil)
	endpoints, err := ParseOpenAPISpec(specJSON, "https://inscope.example.com/openapi.json", sc)
	if err != nil {
		t.Fatalf("ParseOpenAPISpec error: %v", err)
	}

	for _, ep := range endpoints {
		if ep.Origin == "https://evil-external.com" {
			t.Errorf("out-of-scope server was incorrectly parsed: %+v", ep)
		}
		if ep.Origin != "https://inscope.example.com" {
			t.Errorf("unexpected origin: %s", ep.Origin)
		}
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 in-scope endpoint, got %d", len(endpoints))
	}
}

// Regression Scenario 8: External JavaScript URLs must be dropped
func TestRegression8_ExternalJavaScriptURLs(t *testing.T) {
	jsContent := `
		fetch("https://inscope.example.com/api/v1/profile");
		axios.post("https://evil-external.com/api/exfil");
		fetch("https://cdn.thirdparty.com/collect");
		axios.get("/api/v1/internal");
	`

	sc := scope.New([]string{"inscope.example.com"}, nil)
	endpoints := ExtractEndpointsFromJS(jsContent, "https://inscope.example.com/app.js", sc)

	for _, ep := range endpoints {
		if ep.Origin != "https://inscope.example.com" {
			t.Errorf("out-of-scope JS endpoint included: %s (%s)", ep.URL, ep.Origin)
		}
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 in-scope endpoints, got %d: %+v", len(endpoints), endpoints)
	}
}

// Regression Scenario 9: Malformed OpenAPI documents handled without panic
func TestRegression9_MalformedOpenAPIDocuments(t *testing.T) {
	malformedInputs := [][]byte{
		[]byte(`not valid json`),
		[]byte(`{}`),
		[]byte(`{"openapi": "3.0.0"}`),
		[]byte(`{"openapi": "3.0.0", "paths": "invalid_type_not_map"}`),
		[]byte(`{"openapi": "3.0.0", "paths": { "/api": "invalid_operation_map" }}`),
		[]byte(`{"openapi": "3.0.0", "paths": { "/api": { "get": { "parameters": [123, "string"] } } } }`),
	}

	sc := scope.New([]string{"example.com"}, nil)

	for i, input := range malformedInputs {
		t.Run(fmt.Sprintf("malformed_%d", i), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on malformed input %d: %v", i, r)
				}
			}()
			_, _ = ParseOpenAPISpec(input, "https://example.com", sc)
		})
	}
}

// Regression Scenario 10: Concurrent inventory writes and deterministic export
func TestRegression10_ConcurrentInventoryWritesAndDeterministicExport(t *testing.T) {
	inv := NewInventory()
	const numGoroutines = 25
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(routineID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				url := fmt.Sprintf("https://api.example.com/items/%d?cat=books", (routineID*iterations+i)%20)
				inv.AddRawURL(url, "GET", fmt.Sprintf("worker_%d", routineID), nil)
			}
		}(g)
	}

	wg.Wait()

	// Verify count is exactly 1 route template: /items/{id}
	if inv.Count() != 1 {
		t.Fatalf("expected 1 consolidated endpoint for /items/{id}, got %d", inv.Count())
	}

	// Verify deterministic export
	json1, err1 := inv.ToJSON()
	if err1 != nil {
		t.Fatalf("json1 error: %v", err1)
	}

	json2, err2 := inv.ToJSON()
	if err2 != nil {
		t.Fatalf("json2 error: %v", err2)
	}

	if string(json1) != string(json2) {
		t.Errorf("export output was non-deterministic between calls")
	}
}

// Test JS HTTP Methods extraction
func TestExtractEndpointsFromJS_HTTPMethods(t *testing.T) {
	jsCode := `
		axios.post("/api/v1/users", data);
		axios.put("/api/v1/users/42", data);
		axios.delete("/api/v1/users/42");
		axios.patch("/api/v1/orders/10");
		fetch("/api/v1/checkout", { method: "POST" });
		$.post("/api/v1/comments", commentData);
	`

	sc := scope.New([]string{"example.com"}, nil)
	endpoints := ExtractEndpointsFromJS(jsCode, "https://example.com/bundle.js", sc)

	methodMap := map[string]string{}
	for _, ep := range endpoints {
		if len(ep.Methods) > 0 {
			methodMap[ep.NormalizedRoute] = ep.Methods[0]
		}
	}

	if methodMap["/api/v1/users"] != "POST" {
		t.Errorf("expected POST for /api/v1/users, got %s", methodMap["/api/v1/users"])
	}
	if methodMap["/api/v1/checkout"] != "POST" {
		t.Errorf("expected POST for /api/v1/checkout, got %s", methodMap["/api/v1/checkout"])
	}
	if methodMap["/api/v1/comments"] != "POST" {
		t.Errorf("expected POST for /api/v1/comments, got %s", methodMap["/api/v1/comments"])
	}
}

// Test Oversized OpenAPI specification handling
func TestParseOpenAPISpec_Oversized(t *testing.T) {
	oversized := make([]byte, MaxSpecSizeBytes+1024)
	for i := range oversized {
		oversized[i] = ' '
	}

	sc := scope.New([]string{"example.com"}, nil)
	_, err := ParseOpenAPISpec(oversized, "https://example.com", sc)
	if err == nil {
		t.Errorf("expected error for oversized spec, got nil")
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
	if eps[0].NormalizedRoute != "/api/documents" {
		t.Errorf("expected route /api/documents, got %s", eps[0].NormalizedRoute)
	}
}

func TestInventory_GetByClassificationAndFilterInScope(t *testing.T) {
	inv := NewInventory()

	inv.AddRawURL("https://api.example.com/api/v1/upload", "POST", "katana", nil)
	inv.AddRawURL("https://api.example.com/api/v1/users/42", "GET", "katana", nil)
	inv.AddRawURL("https://out-of-scope.example.org/api/v1/status", "GET", "katana", nil)

	if inv.Count() != 3 {
		t.Fatalf("expected 3 endpoints, got %d", inv.Count())
	}

	// Test GetByClassification
	fileUploads := inv.GetByClassification(ClassFileProcess)
	if len(fileUploads) != 1 {
		t.Errorf("expected 1 file upload endpoint, got %d", len(fileUploads))
	}

	userData := inv.GetByClassification(ClassUserData)
	if len(userData) != 1 {
		t.Errorf("expected 1 user data endpoint, got %d", len(userData))
	}

	// Test FilterInScope
	sc := scope.New([]string{"api.example.com"}, nil)
	inv.FilterInScope(sc)

	if inv.Count() != 2 {
		t.Errorf("expected 2 endpoints after FilterInScope, got %d", inv.Count())
	}

	// Test JSON roundtrip (ToJSON and FromJSON)
	data, err := inv.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	inv2 := NewInventory()
	if err := inv2.FromJSON(data); err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}

	if inv2.Count() != 2 {
		t.Errorf("expected 2 endpoints in restored inventory, got %d", inv2.Count())
	}
}

func TestExtractOrigin(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://api.example.com:8443/v1/users", "https://api.example.com:8443"},
		{"http://example.com/test", "http://example.com"},
		{"//example.com/test", "https://example.com"},
		{"", ""},
	}

	for _, tc := range tests {
		got := ExtractOrigin(tc.url)
		if got != tc.expected {
			t.Errorf("ExtractOrigin(%q) = %q, expected %q", tc.url, got, tc.expected)
		}
	}
}

func TestParseOpenAPISpec_SchemaProperties(t *testing.T) {
	specJSON := []byte(`{
		"openapi": "3.0.0",
		"info": { "title": "Nested API", "version": "1.0" },
		"paths": {
			"/submit": {
				"post": {
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"properties": {
										"username": { "type": "string" },
										"profile": {
											"properties": {
												"bio": { "type": "string" },
												"avatar_url": { "type": "string" }
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}`)

	sc := scope.New([]string{"example.com"}, nil)
	endpoints, err := ParseOpenAPISpec(specJSON, "https://example.com/api", sc)
	if err != nil {
		t.Fatalf("ParseOpenAPISpec error: %v", err)
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}

	fields := endpoints[0].BodyFields
	fieldMap := map[string]bool{}
	for _, f := range fields {
		fieldMap[f] = true
	}

	if !fieldMap["username"] || !fieldMap["profile.bio"] || !fieldMap["profile.avatar_url"] {
		t.Errorf("missing expected nested schema fields in %v", fields)
	}
}
