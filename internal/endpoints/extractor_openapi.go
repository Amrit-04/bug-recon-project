package endpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

// Standard Swagger and OpenAPI discovery locations
var StandardAPISpecPaths = []string{
	"/openapi.json",
	"/swagger.json",
	"/api-docs",
	"/v2/api-docs",
	"/v3/api-docs",
	"/swagger/v1/swagger.json",
	"/api/swagger.json",
	"/api/v1/swagger.json",
	"/api/openapi.json",
}

// ParseOpenAPISpec parses an OpenAPI 3.x or Swagger 2.0 document into structured Endpoint records.
func ParseOpenAPISpec(data []byte, baseURL string, s *scope.Scope) ([]*Endpoint, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse OpenAPI JSON: %w", err)
	}

	// Verify it looks like Swagger or OpenAPI
	_, hasSwagger := raw["swagger"]
	_, hasOpenAPI := raw["openapi"]
	if !hasSwagger && !hasOpenAPI {
		return nil, fmt.Errorf("document missing swagger or openapi version field")
	}

	pathsRaw, ok := raw["paths"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("document missing valid paths object")
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Determine base path (Swagger 2.0 has basePath property)
	basePath := ""
	if bp, ok := raw["basePath"].(string); ok {
		basePath = bp
	}

	var results []*Endpoint
	for routePath, methodsObj := range pathsRaw {
		methodsMap, ok := methodsObj.(map[string]any)
		if !ok {
			continue
		}

		fullPath := pathJoin(basePath, routePath)
		targetURL := base.ResolveReference(&url.URL{Path: fullPath}).String()

		if s != nil && !s.IsURLInScope(targetURL) {
			continue
		}

		canonicalURL, normalizedRoute, _, _ := NormalizeURL(targetURL)

		for httpMethod, opDetails := range methodsMap {
			methodUpper := strings.ToUpper(httpMethod)
			if !isHTTPMethod(methodUpper) {
				continue
			}

			opMap, _ := opDetails.(map[string]any)

			var queryParams []string
			var bodyFields []string
			var contentTypes []string
			authRequired := false

			// Inspect parameters
			if paramsList, ok := opMap["parameters"].([]any); ok {
				for _, pItem := range paramsList {
					if pMap, ok := pItem.(map[string]any); ok {
						pName, _ := pMap["name"].(string)
						pIn, _ := pMap["in"].(string)
						if pIn == "query" && pName != "" {
							queryParams = append(queryParams, pName)
						} else if pIn == "body" {
							// Swagger 2.0 body schema
							if schema, ok := pMap["schema"].(map[string]any); ok {
								bodyFields = append(bodyFields, extractSchemaFields(schema)...)
							}
						}
					}
				}
			}

			// Inspect requestBody (OpenAPI 3.x)
			if reqBody, ok := opMap["requestBody"].(map[string]any); ok {
				if content, ok := reqBody["content"].(map[string]any); ok {
					for cType, cDetails := range content {
						contentTypes = append(contentTypes, cType)
						if cMap, ok := cDetails.(map[string]any); ok {
							if schema, ok := cMap["schema"].(map[string]any); ok {
								bodyFields = append(bodyFields, extractSchemaFields(schema)...)
							}
						}
					}
				}
			}

			// Inspect consumes (Swagger 2.0)
			if consumes, ok := opMap["consumes"].([]any); ok {
				for _, c := range consumes {
					if cs, ok := c.(string); ok {
						contentTypes = append(contentTypes, cs)
					}
				}
			}

			// Inspect security requirements
			if sec, ok := opMap["security"].([]any); ok && len(sec) > 0 {
				authRequired = true
			} else if globalSec, ok := raw["security"].([]any); ok && len(globalSec) > 0 {
				authRequired = true
			}

			sort.Strings(queryParams)
			sort.Strings(bodyFields)

			ep := &Endpoint{
				URL:             canonicalURL,
				NormalizedRoute: normalizedRoute,
				Methods:         []string{methodUpper},
				QueryParams:     uniqueStrings(queryParams),
				BodyFields:      uniqueStrings(bodyFields),
				ContentTypes:    uniqueStrings(contentTypes),
				AuthRequired:    authRequired,
				Sources:         []string{"openapi_spec"},
				Classifications: ClassifyEndpoint(normalizedRoute, queryParams, bodyFields, contentTypes),
			}
			results = append(results, ep)
		}
	}

	return results, nil
}

// DiscoverPublicAPISpec probes known OpenAPI/Swagger endpoints on a target host using the scope-enforcing HTTP client.
func DiscoverPublicAPISpec(ctx context.Context, client *httpx.Client, host string, s *scope.Scope) ([]*Endpoint, string) {
	if client == nil || host == "" {
		return nil, ""
	}

	scheme := "https"
	if strings.HasPrefix(host, "http://") {
		scheme = "http"
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	for _, specPath := range StandardAPISpecPaths {
		targetURL := fmt.Sprintf("%s://%s%s", scheme, host, specPath)

		if s != nil && !s.IsURLInScope(targetURL) {
			continue
		}

		resp, err := client.Get(ctx, targetURL)
		if err != nil || resp == nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil && len(body) > 20 {
				endpoints, parseErr := ParseOpenAPISpec(body, targetURL, s)
				if parseErr == nil && len(endpoints) > 0 {
					return endpoints, targetURL
				}
			}
		} else {
			resp.Body.Close()
		}
	}

	return nil, ""
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func pathJoin(base, elem string) string {
	base = strings.TrimSuffix(base, "/")
	elem = strings.TrimPrefix(elem, "/")
	if base == "" {
		return "/" + elem
	}
	return base + "/" + elem
}

func extractSchemaFields(schema map[string]any) []string {
	var fields []string
	if props, ok := schema["properties"].(map[string]any); ok {
		for propName, propVal := range props {
			fields = append(fields, propName)
			if subMap, ok := propVal.(map[string]any); ok {
				if subProps, ok := subMap["properties"].(map[string]any); ok {
					for subName := range subProps {
						fields = append(fields, propName+"."+subName)
					}
				}
			}
		}
	}
	return fields
}
