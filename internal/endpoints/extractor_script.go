package endpoints

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/scoutr/scoutr/internal/scope"
)

var (
	// Regex matching endpoint strings in JS: "/api/v1/users", "/v2/auth/login", "/upload", etc.
	jsEndpointLiteralRegex = regexp.MustCompile(`(?i)["'\x60](/(?:api|v[0-9]+|rest|graphql|admin|auth|user|account|doc|file|upload|template|job|webhook|convert|export|import)/[a-zA-Z0-9_\-\./{}?&=%:]*)["'\x60]`)

	// Regex matching fetch/axios/http calls in JS: fetch("/path"), axios.get("/path"), etc.
	jsFetchCallRegex = regexp.MustCompile(`(?i)(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.(?:get|post|ajax))\s*\(\s*["'\x60](/[^"'\x60\s\)]+)["'\x60]`)

	// Static asset extensions to ignore
	staticExtRegex = regexp.MustCompile(`(?i)\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|webm|webp)$`)
)

// ExtractEndpointsFromJS scans JavaScript file content for referenced API routes and endpoints.
// Resolves relative routes against baseURL and filters with scope.
func ExtractEndpointsFromJS(jsContent string, baseURL string, s *scope.Scope) []*Endpoint {
	if jsContent == "" {
		return nil
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var endpoints []*Endpoint

	// 1. Scan literal paths
	matches := jsEndpointLiteralRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range matches {
		if len(m) > 1 {
			relPath := m[1]
			ep := processJSRoute(relPath, base, s, seen)
			if ep != nil {
				endpoints = append(endpoints, ep)
			}
		}
	}

	// 2. Scan fetch / axios calls
	fetchMatches := jsFetchCallRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range fetchMatches {
		if len(m) > 1 {
			relPath := m[1]
			ep := processJSRoute(relPath, base, s, seen)
			if ep != nil {
				endpoints = append(endpoints, ep)
			}
		}
	}

	return endpoints
}

func processJSRoute(relPath string, base *url.URL, s *scope.Scope, seen map[string]bool) *Endpoint {
	relPath = strings.TrimSpace(relPath)
	if relPath == "" || staticExtRegex.MatchString(relPath) {
		return nil
	}

	// Clean path
	relPath = path.Clean(relPath)
	if !strings.HasPrefix(relPath, "/") {
		relPath = "/" + relPath
	}

	// Resolve against base
	fullURL := base.ResolveReference(&url.URL{Path: relPath}).String()

	if s != nil && !s.IsURLInScope(fullURL) {
		return nil
	}

	canonicalURL, route, params, _ := NormalizeURL(fullURL)
	if route == "" || seen[route] {
		return nil
	}
	seen[route] = true

	ep := &Endpoint{
		URL:             canonicalURL,
		NormalizedRoute: route,
		Methods:         []string{"GET"},
		QueryParams:     params,
		Sources:         []string{"js_extract"},
		Classifications: ClassifyEndpoint(route, params, nil, nil),
	}
	return ep
}
