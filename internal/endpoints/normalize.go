package endpoints

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	// Integer segment: e.g. /1234/
	integerSegmentRegex = regexp.MustCompile(`^[0-9]+$`)

	// UUID segment: e.g. /123e4567-e89b-12d3-a456-426614174000/
	uuidSegmentRegex = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	// Hash/Hex segment (MD5, SHA1, SHA256): e.g. 32 or 40 or 64 hex chars
	hexSegmentRegex = regexp.MustCompile(`(?i)^[0-9a-f]{32,64}$`)

	// Sensitive query or body parameter keys that carry credentials, tokens, or security nonces.
	// These must NEVER be extracted as object IDs or sent to LLM prompts.
	sensitiveParamRegex = regexp.MustCompile(`(?i)(token|password|passwd|secret|auth|bearer|jwt|key|signature|sig|credential|cookie|session|csrf|xsrf|api_key|apikey|access_token|refresh_token|private)`)
)

// ObjectIDCandidate represents an identifier found in a route or query parameter that may reference an object.
type ObjectIDCandidate struct {
	Type     string `json:"type"`               // "path", "query", "body"
	Name     string `json:"name"`               // parameter name or path segment identifier
	Value    string `json:"value"`              // actual value observed
	Kind     string `json:"kind"`               // "integer", "uuid", "hash", "string"
	Endpoint string `json:"endpoint,omitempty"` // URL where observed
}

// NormalizeURL canonicalizes a raw URL into:
// - origin: scheme://host[:port] (e.g. "https://api.example.com:8443")
// - canonicalURL: normalized URL with sorted query parameter keys
// - normalizedRoute: parameterized route template starting with "/" (e.g. "/api/v1/users/{id}")
// - queryParams: unique sorted query parameter keys
// - candidates: extracted concrete object identifiers for IDOR research
func NormalizeURL(rawURL string) (origin string, canonicalURL string, normalizedRoute string, queryParams []string, candidates []ObjectIDCandidate) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "", "", nil, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", rawURL, rawURL, nil, nil
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.Fragment = "" // Strip anchor fragments

	if u.Host != "" {
		origin = fmt.Sprintf("%s://%s", scheme, u.Host)
	}

	// Normalize query parameters (keys sorted, values not stored in queryParams list)
	q := u.Query()
	paramKeys := make([]string, 0, len(q))
	for k, vals := range q {
		cleanKey := strings.TrimSpace(k)
		if cleanKey != "" {
			paramKeys = append(paramKeys, cleanKey)

			// Never extract sensitive keys (tokens, passwords, signatures) as object ID candidates
			if sensitiveParamRegex.MatchString(cleanKey) {
				continue
			}

			// Inspect query parameter values for candidate IDs
			for _, val := range vals {
				val = strings.TrimSpace(val)
				if val == "" {
					continue
				}
				if isCandidateID(cleanKey, val) {
					candidates = append(candidates, ObjectIDCandidate{
						Type:     "query",
						Name:     cleanKey,
						Value:    val,
						Kind:     detectIDKind(val),
						Endpoint: rawURL,
					})
				}
			}
		}
	}
	sort.Strings(paramKeys)

	// Clean path
	cleanPath := path.Clean(u.Path)
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "/"
	}
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	// Tokenize path segments
	segments := strings.Split(cleanPath, "/")
	normalizedSegments := make([]string, len(segments))

	for i, seg := range segments {
		if seg == "" {
			normalizedSegments[i] = ""
			continue
		}

		if integerSegmentRegex.MatchString(seg) {
			normalizedSegments[i] = "{id}"
			candidates = append(candidates, ObjectIDCandidate{
				Type:     "path",
				Name:     pathSegmentName(segments, i),
				Value:    seg,
				Kind:     "integer",
				Endpoint: rawURL,
			})
		} else if uuidSegmentRegex.MatchString(seg) {
			normalizedSegments[i] = "{uuid}"
			candidates = append(candidates, ObjectIDCandidate{
				Type:     "path",
				Name:     pathSegmentName(segments, i),
				Value:    seg,
				Kind:     "uuid",
				Endpoint: rawURL,
			})
		} else if hexSegmentRegex.MatchString(seg) {
			normalizedSegments[i] = "{hash}"
			candidates = append(candidates, ObjectIDCandidate{
				Type:     "path",
				Name:     pathSegmentName(segments, i),
				Value:    seg,
				Kind:     "hash",
				Endpoint: rawURL,
			})
		} else {
			normalizedSegments[i] = seg
		}
	}

	normalizedRoute = strings.Join(normalizedSegments, "/")
	if !strings.HasPrefix(normalizedRoute, "/") {
		normalizedRoute = "/" + normalizedRoute
	}

	// Canonical URL reconstruct
	u.RawQuery = q.Encode()
	canonicalURL = u.String()

	return origin, canonicalURL, normalizedRoute, paramKeys, candidates
}

// pathSegmentName tries to infer a contextual name for a path segment ID (e.g. from preceding segment).
func pathSegmentName(segments []string, idx int) string {
	if idx > 0 && segments[idx-1] != "" {
		parent := strings.ToLower(segments[idx-1])
		return strings.TrimSuffix(parent, "s") + "_id"
	}
	return "id"
}

// isCandidateID checks if a parameter key and value match typical object identifiers.
func isCandidateID(key, value string) bool {
	lowerKey := strings.ToLower(key)

	// Block any secret/token parameters from being considered object IDs
	if sensitiveParamRegex.MatchString(lowerKey) {
		return false
	}

	if strings.Contains(lowerKey, "id") || strings.Contains(lowerKey, "user") ||
		strings.Contains(lowerKey, "account") || strings.Contains(lowerKey, "doc") ||
		strings.Contains(lowerKey, "file") || strings.Contains(lowerKey, "order") ||
		strings.Contains(lowerKey, "item") || strings.Contains(lowerKey, "num") ||
		strings.Contains(lowerKey, "uuid") || strings.Contains(lowerKey, "guid") ||
		strings.Contains(lowerKey, "report") || strings.Contains(lowerKey, "invoice") ||
		strings.Contains(lowerKey, "folder") || strings.Contains(lowerKey, "project") {
		return integerSegmentRegex.MatchString(value) || uuidSegmentRegex.MatchString(value) || hexSegmentRegex.MatchString(value)
	}

	// Value strongly resembles a UUID or numerical ID
	return integerSegmentRegex.MatchString(value) || uuidSegmentRegex.MatchString(value)
}

func detectIDKind(val string) string {
	if integerSegmentRegex.MatchString(val) {
		return "integer"
	}
	if uuidSegmentRegex.MatchString(val) {
		return "uuid"
	}
	if hexSegmentRegex.MatchString(val) {
		return "hash"
	}
	return "string"
}
