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

// MaxSpecSizeBytes bounds the maximum acceptable OpenAPI document size to 5 MB to prevent memory exhaustion.
const MaxSpecSizeBytes = 5 * 1024 * 1024

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
// Strictly enforces scope boundaries on OpenAPI server definitions and discards external $ref references.
func ParseOpenAPISpec(data []byte, baseURL string, s *scope.Scope) ([]*Endpoint, error) {
	if len(data) > MaxSpecSizeBytes {
		return nil, fmt.Errorf("OpenAPI specification exceeds size limit of %d bytes", MaxSpecSizeBytes)
	}

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

	// Resolve server bases: OpenAPI 3.x defines "servers", Swagger 2.0 defines "basePath"
	var serverBases []*url.URL

	if serversList, ok := raw["servers"].([]any); ok && len(serversList) > 0 {
		for _, sItem := range serversList {
			sMap, ok := sItem.(map[string]any)
			if !ok {
				continue
			}
			serverURLStr, _ := sMap["url"].(string)
			serverURLStr = strings.TrimSpace(serverURLStr)
			if serverURLStr == "" {
				continue
			}

			// Resolve relative or absolute server URL
			var resolvedServer *url.URL
			if strings.HasPrefix(serverURLStr, "http://") || strings.HasPrefix(serverURLStr, "https://") {
				resolvedServer, err = url.Parse(serverURLStr)
			} else {
				resolvedServer, err = base.Parse(serverURLStr)
			}

			if err != nil || resolvedServer == nil {
				continue
			}

			// Strictly check if server declaration is in scope!
			if s != nil && !s.IsURLInScope(resolvedServer.String()) {
				// Out-of-scope server declaration in spec must be rejected!
				continue
			}

			serverBases = append(serverBases, resolvedServer)
		}
	}

	// If no valid servers found from OpenAPI 3.x "servers", fallback to Swagger 2.0 basePath or base URL
	if len(serverBases) == 0 {
		basePath := ""
		if bp, ok := raw["basePath"].(string); ok {
			basePath = bp
		}
		fallbackURL := base.ResolveReference(&url.URL{Path: basePath})
		if s == nil || s.IsURLInScope(fallbackURL.String()) {
			serverBases = append(serverBases, fallbackURL)
		}
	}

	// If all servers were out of scope, return empty result
	if len(serverBases) == 0 {
		return nil, nil
	}

	var results []*Endpoint
	for routePath, methodsObj := range pathsRaw {
		methodsMap, ok := methodsObj.(map[string]any)
		if !ok {
			continue
		}

		for _, serverBase := range serverBases {
			fullPath := pathJoin(serverBase.Path, routePath)
			targetURL := serverBase.ResolveReference(&url.URL{Path: fullPath}).String()

			if s != nil && !s.IsURLInScope(targetURL) {
				continue
			}

			origin, canonicalURL, normalizedRoute, _, candidates := NormalizeURL(targetURL)

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
							// Discard external $ref in parameters
							if isExternalRef(pMap["$ref"]) {
								continue
							}

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
					Origin:          origin,
					URL:             canonicalURL,
					NormalizedRoute: normalizedRoute,
					Methods:         []string{methodUpper},
					ObservedURLs:    []string{canonicalURL},
					ObservedObjects: candidates,
					QueryParams:     uniqueStrings(queryParams),
					BodyFields:      uniqueStrings(bodyFields),
					ContentTypes:    uniqueStrings(contentTypes),
					AuthRequired:    authRequired,
					Sources:         []string{"openapi_spec"},
					Classifications: ClassifyEndpoint(normalizedRoute, queryParams, bodyFields, contentTypes),
				}

				if authRequired {
					ep.AddAuthObservation(AuthObservation{
						Status:   AuthStatusAuthenticated,
						AuthType: "unknown",
						Source:   "openapi_spec",
					})
				}

				results = append(results, ep)
			}
		}
	}

	return results, nil
}

// DiscoverPublicAPISpec probes known OpenAPI/Swagger endpoints on a target host using the scope-enforcing HTTP client.
// Limits read size to MaxSpecSizeBytes.
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
			// Limit reader to MaxSpecSizeBytes + 1 to detect oversized responses
			lr := io.LimitReader(resp.Body, MaxSpecSizeBytes+1)
			body, readErr := io.ReadAll(lr)
			resp.Body.Close()

			if readErr == nil && len(body) > 20 && len(body) <= MaxSpecSizeBytes {
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
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE":
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

func isExternalRef(ref any) bool {
	refStr, ok := ref.(string)
	if !ok {
		return false
	}
	refStr = strings.TrimSpace(refStr)
	return strings.HasPrefix(refStr, "http://") || strings.HasPrefix(refStr, "https://") || strings.HasPrefix(refStr, "//")
}

func extractSchemaFields(schema map[string]any) []string {
	var fields []string
	if isExternalRef(schema["$ref"]) {
		return nil
	}

	if props, ok := schema["properties"].(map[string]any); ok {
		for propName, propVal := range props {
			fields = append(fields, propName)
			if subMap, ok := propVal.(map[string]any); ok {
				if isExternalRef(subMap["$ref"]) {
					continue
				}
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
