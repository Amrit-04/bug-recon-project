package endpoints

import (
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/scoutr/scoutr/internal/scope"
)

// MaxScriptScanBytes caps the size of JavaScript files parsed to 5 MB to prevent regex backtracking/DoS.
const MaxScriptScanBytes = 5 * 1024 * 1024

var (
	// Matches relative API route string literals: "/api/v1/users", "/admin/settings", etc.
	jsRelativeRouteRegex = regexp.MustCompile(`(?i)["'\x60](/(?:api|v[0-9]+|rest|graphql|admin|auth|user|account|doc|file|upload|template|job|webhook|convert|export|import)/[a-zA-Z0-9_\-\./{}?&=%:]*)["'\x60]`)

	// Matches absolute HTTP/HTTPS API URLs: "https://api.example.com/v1/users", "http://dev.target.com/api"
	jsAbsoluteURLRegex = regexp.MustCompile(`(?i)["'\x60](https?://[a-zA-Z0-9\-\.:]+/(?:api|v[0-9]+|rest|graphql|admin|auth|user|account|doc|file|upload|template|job|webhook|convert|export|import)[a-zA-Z0-9_\-\./{}?&=%:]*)["'\x60]`)

	// Matches axios method calls: axios.post("/path"), axios.delete("https://..."), axios.put(...)
	jsAxiosMethodRegex = regexp.MustCompile(`(?i)axios\.(get|post|put|delete|patch)\s*\(\s*["'\x60]([^"'\x60\s\)]+)["'\x60]`)

	// Matches jQuery ajax calls: $.get("/path"), $.post("/path")
	jsJQueryMethodRegex = regexp.MustCompile(`(?i)\$\.(get|post)\s*\(\s*["'\x60]([^"'\x60\s\)]+)["'\x60]`)

	// Matches fetch calls with optional method config: fetch("/path", { method: "POST" })
	jsFetchCallRegex = regexp.MustCompile(`(?i)fetch\s*\(\s*["'\x60]([^"'\x60\s\)]+)["'\x60](?:\s*,\s*\{[^}]*method\s*:\s*["'\x60]([a-zA-Z]+)["'\x60])?`)

	// Static asset extensions to ignore
	staticExtRegex = regexp.MustCompile(`(?i)\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|webm|webp|js|map)$`)
)

type jsEndpointEntry struct {
	ep                *Endpoint
	hasExplicitMethod bool
}

// ExtractEndpointsFromJS scans JavaScript file content for referenced API routes and endpoints.
// Supports both relative and absolute URLs, extracts HTTP methods from fetch/axios patterns,
// enforces strict scope checking, and rejects out-of-scope or malformed references.
func ExtractEndpointsFromJS(jsContent string, baseURL string, s *scope.Scope) []*Endpoint {
	if jsContent == "" {
		return nil
	}

	if len(jsContent) > MaxScriptScanBytes {
		jsContent = jsContent[:MaxScriptScanBytes]
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	endpointMap := make(map[string]*jsEndpointEntry)

	recordItem := func(target, method string, hasExplicitMethod bool) {
		ep := processJSItem(target, method, base, s)
		if ep == nil {
			return
		}
		key := ep.Origin + ep.NormalizedRoute
		existing, found := endpointMap[key]
		if !found {
			endpointMap[key] = &jsEndpointEntry{
				ep:                ep,
				hasExplicitMethod: hasExplicitMethod,
			}
		} else {
			if hasExplicitMethod {
				if !existing.hasExplicitMethod {
					// Upgrade generic GET to the explicit method
					existing.ep.Methods = []string{method}
					existing.hasExplicitMethod = true
				} else {
					// Add method if distinct
					foundMethod := false
					for _, m := range existing.ep.Methods {
						if m == method {
							foundMethod = true
							break
						}
					}
					if !foundMethod {
						existing.ep.Methods = append(existing.ep.Methods, method)
					}
				}
			}
		}
	}

	// 1. Scan axios method calls: axios.post, axios.put, etc.
	axiosMatches := jsAxiosMethodRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range axiosMatches {
		if len(m) > 2 {
			method := strings.ToUpper(m[1])
			target := m[2]
			recordItem(target, method, true)
		}
	}

	// 2. Scan jQuery method calls: $.get, $.post
	jqMatches := jsJQueryMethodRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range jqMatches {
		if len(m) > 2 {
			method := strings.ToUpper(m[1])
			target := m[2]
			recordItem(target, method, true)
		}
	}

	// 3. Scan fetch calls with optional method
	fetchMatches := jsFetchCallRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range fetchMatches {
		if len(m) > 1 {
			target := m[1]
			method := "GET"
			hasExplicitMethod := false
			if len(m) > 2 && m[2] != "" {
				method = strings.ToUpper(m[2])
				hasExplicitMethod = true
			}
			recordItem(target, method, hasExplicitMethod)
		}
	}

	// 4. Scan absolute URL literals: https://...
	absMatches := jsAbsoluteURLRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range absMatches {
		if len(m) > 1 {
			target := m[1]
			recordItem(target, "GET", false)
		}
	}

	// 5. Scan relative route literals: "/api/..."
	relMatches := jsRelativeRouteRegex.FindAllStringSubmatch(jsContent, -1)
	for _, m := range relMatches {
		if len(m) > 1 {
			target := m[1]
			recordItem(target, "GET", false)
		}
	}

	out := make([]*Endpoint, 0, len(endpointMap))
	for _, entry := range endpointMap {
		out = append(out, entry.ep)
	}

	return out
}

func processJSItem(target, method string, base *url.URL, s *scope.Scope) *Endpoint {
	target = strings.TrimSpace(target)
	if target == "" || staticExtRegex.MatchString(target) {
		return nil
	}

	// Ignore template string interpolations like "${id}" or javascript code snippets
	if strings.Contains(target, "${") || strings.Contains(target, "<") || strings.Contains(target, ">") {
		return nil
	}

	var fullURL string
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		// Absolute URL
		fullURL = target
	} else if strings.HasPrefix(target, "//") {
		// Protocol-relative URL
		scheme := "https"
		if base != nil && base.Scheme != "" {
			scheme = base.Scheme
		}
		fullURL = scheme + ":" + target
	} else {
		// Relative path
		relPath := path.Clean(target)
		if !strings.HasPrefix(relPath, "/") {
			relPath = "/" + relPath
		}
		if base != nil {
			fullURL = base.ResolveReference(&url.URL{Path: relPath}).String()
		} else {
			return nil
		}
	}

	// Strictly verify that the full resolved URL is in scope!
	if s != nil && !s.IsURLInScope(fullURL) {
		return nil
	}

	origin, canonicalURL, route, params, candidates := NormalizeURL(fullURL)
	if route == "" {
		return nil
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	ep := &Endpoint{
		Origin:          origin,
		URL:             canonicalURL,
		NormalizedRoute: route,
		Methods:         []string{method},
		ObservedURLs:    []string{canonicalURL},
		ObservedObjects: candidates,
		QueryParams:     params,
		Sources:         []string{"js_extract"},
		Classifications: ClassifyEndpoint(route, params, nil, nil),
	}
	return ep
}
