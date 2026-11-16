package idor

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
)

// ObjectLocation indicates where an object reference was discovered.
type ObjectLocation string

const (
	LocationPath     ObjectLocation = "path"
	LocationQuery    ObjectLocation = "query"
	LocationBody     ObjectLocation = "body"
	LocationResponse ObjectLocation = "response"
	LocationAPISpec  ObjectLocation = "api_spec"
)

var (
	integerRegex = regexp.MustCompile(`^[0-9]+$`)
	uuidRegex    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexHashRegex = regexp.MustCompile(`(?i)^[0-9a-f]{32,64}$`)

	// Non-object parameter names to strictly exclude
	nonObjectParamRegex = regexp.MustCompile(`(?i)^(page|p|limit|offset|size|per_page|count|skip|take|page_size|max_results|sort|order|by|direction|dir|asc|desc|format|output|f|v|version|api_version|debug|verbose|raw|force|refresh|ts|timestamp|created_at|updated_at|date|time|year|month|day|epoch|token|jwt|auth|bearer|secret|signature|sig|key|cookie|session|csrf|xsrf|q|query|search|filter|term|keyword|lang|locale)$`)

	// High-confidence entity keywords
	entityNounRegex = regexp.MustCompile(`(?i)(user|account|profile|member|customer|client|doc|document|file|report|invoice|order|item|payment|wallet|transaction|project|folder|task|ticket|message|post|comment|record|asset|note|device)`)
)

// IsContextualObjectID applies deterministic heuristics to verify if a token represents an object identifier
// rather than pagination, a status code, boolean flag, or transient value.
func IsContextualObjectID(paramName, value string, loc ObjectLocation, parentRoute string) bool {
	paramName = strings.TrimSpace(paramName)
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	// 1. Strictly block known non-object parameters
	if nonObjectParamRegex.MatchString(paramName) {
		return false
	}

	// 2. Reject boolean strings or trivial flags
	if value == "true" || value == "false" || value == "null" || value == "undefined" {
		return false
	}

	// 3. Reject numbers that look like HTTP status codes
	if integerRegex.MatchString(value) {
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			// Status codes or zero/single digits with generic param name
			if intVal == 0 && !entityNounRegex.MatchString(paramName) {
				return false
			}
			if (intVal >= 100 && intVal <= 599) && (strings.Contains(strings.ToLower(paramName), "status") || strings.Contains(strings.ToLower(paramName), "code")) {
				return false
			}
			// Unix timestamps (values around 1.7 billion)
			if intVal >= 1600000000 && intVal <= 2100000000 {
				return false
			}
		}
	}

	// 4. Inspect UUIDs: UUIDs are almost universally unique entity identifiers
	if uuidRegex.MatchString(value) {
		return true
	}

	// 5. Inspect parameter name
	lowerParam := strings.ToLower(paramName)
	if entityNounRegex.MatchString(lowerParam) {
		return integerRegex.MatchString(value) || hexHashRegex.MatchString(value) || len(value) >= 3
	}
	if strings.HasSuffix(lowerParam, "id") || strings.HasSuffix(lowerParam, "_id") || strings.HasSuffix(lowerParam, "guid") {
		return integerRegex.MatchString(value) || hexHashRegex.MatchString(value) || len(value) >= 3
	}

	// 6. Inspect path location context
	if loc == LocationPath {
		// Parent path segment should be an entity noun (e.g. /users/{id})
		parent := strings.ToLower(parentRoute)
		if entityNounRegex.MatchString(parent) {
			return integerRegex.MatchString(value) || hexHashRegex.MatchString(value)
		}
	}

	return false
}

// InferObjectType derives the business entity type (e.g. "user", "document", "invoice") from parameter/route context.
func InferObjectType(paramName, routeTemplate string) string {
	lowerParam := strings.ToLower(paramName)
	if m := entityNounRegex.FindString(lowerParam); m != "" {
		return m
	}

	lowerRoute := strings.ToLower(routeTemplate)
	if m := entityNounRegex.FindString(lowerRoute); m != "" {
		return m
	}

	return "resource"
}

// ExtractCandidatesFromEndpoint inspects an inventory Endpoint and returns contextual object references.
func ExtractCandidatesFromEndpoint(ep *endpoints.Endpoint) []ObjectReference {
	if ep == nil {
		return nil
	}

	var refs []ObjectReference
	seen := make(map[string]bool)

	// Owner principal and tenant if available from auth observations
	ownerPrincipal := "unknown"
	ownerTenant := "unknown"
	for _, obs := range ep.AuthObservations {
		if obs.Status == endpoints.AuthStatusAuthenticated && obs.PrincipalLabel != "" {
			ownerPrincipal = obs.PrincipalLabel
			if obs.TenantLabel != "" {
				ownerTenant = obs.TenantLabel
			}
			break
		}
	}

	method := "GET"
	if len(ep.Methods) > 0 {
		method = ep.Methods[0]
	}

	// Extract from observed objects
	for _, obj := range ep.ObservedObjects {
		loc := LocationPath
		if obj.Type == "query" {
			loc = LocationQuery
		} else if obj.Type == "body" {
			loc = LocationBody
		}

		if !IsContextualObjectID(obj.Name, obj.Value, loc, ep.NormalizedRoute) {
			continue
		}

		ref := ObjectReference{
			ID:             generateRefID(loc, ep.NormalizedRoute, obj.Name, obj.Value),
			ObjectID:       obj.Value,
			Kind:           obj.Kind,
			Location:       loc,
			ParamName:      obj.Name,
			ObjectType:     InferObjectType(obj.Name, ep.NormalizedRoute),
			RouteTemplate:  ep.NormalizedRoute,
			TargetURL:      ep.URL,
			Method:         method,
			OwnerPrincipal: ownerPrincipal,
			OwnerTenant:    ownerTenant,
			Source:         "endpoints",
			DiscoveredAt:   time.Now(),
		}

		if !seen[ref.ID] {
			seen[ref.ID] = true
			refs = append(refs, ref)
		}
	}

	return refs
}

// ExtractCandidatesFromHAR extracts candidate object references from imported HAR transactions.
func ExtractCandidatesFromHAR(entries []*auth.ImportedHAREntry, ownerPrincipal, ownerTenant string) []ObjectReference {
	var refs []ObjectReference
	seen := make(map[string]bool)

	for _, entry := range entries {
		u, err := url.Parse(entry.URL)
		if err != nil {
			continue
		}

		cleanPath := path.Clean(u.Path)
		segments := strings.Split(cleanPath, "/")

		// 1. Path segments
		for i, seg := range segments {
			if seg == "" {
				continue
			}
			parentName := "id"
			if i > 0 && segments[i-1] != "" {
				parentName = strings.TrimSuffix(strings.ToLower(segments[i-1]), "s") + "_id"
			}
			if IsContextualObjectID(parentName, seg, LocationPath, cleanPath) {
				kind := "string"
				if integerRegex.MatchString(seg) {
					kind = "integer"
				} else if uuidRegex.MatchString(seg) {
					kind = "uuid"
				}

				ref := ObjectReference{
					ID:             generateRefID(LocationPath, cleanPath, parentName, seg),
					ObjectID:       seg,
					Kind:           kind,
					Location:       LocationPath,
					ParamName:      parentName,
					ObjectType:     InferObjectType(parentName, cleanPath),
					RouteTemplate:  cleanPath,
					TargetURL:      entry.URL,
					Method:         entry.Method,
					OwnerPrincipal: ownerPrincipal,
					OwnerTenant:    ownerTenant,
					Source:         "har_import",
					DiscoveredAt:   entry.Timestamp,
				}
				if !seen[ref.ID] {
					seen[ref.ID] = true
					refs = append(refs, ref)
				}
			}
		}

		// 2. Query parameters
		for k, v := range entry.QueryParams {
			if IsContextualObjectID(k, v, LocationQuery, cleanPath) {
				kind := "string"
				if integerRegex.MatchString(v) {
					kind = "integer"
				} else if uuidRegex.MatchString(v) {
					kind = "uuid"
				}

				ref := ObjectReference{
					ID:             generateRefID(LocationQuery, cleanPath, k, v),
					ObjectID:       v,
					Kind:           kind,
					Location:       LocationQuery,
					ParamName:      k,
					ObjectType:     InferObjectType(k, cleanPath),
					RouteTemplate:  cleanPath,
					TargetURL:      entry.URL,
					Method:         entry.Method,
					OwnerPrincipal: ownerPrincipal,
					OwnerTenant:    ownerTenant,
					Source:         "har_import",
					DiscoveredAt:   entry.Timestamp,
				}
				if !seen[ref.ID] {
					seen[ref.ID] = true
					refs = append(refs, ref)
				}
			}
		}

		// 3. Response JSON bodies
		if entry.ResponseBody != "" && strings.HasPrefix(strings.TrimSpace(entry.ResponseBody), "{") {
			bodyRefs := extractFromJSONMap([]byte(entry.ResponseBody), entry.URL, cleanPath, LocationResponse, ownerPrincipal, ownerTenant, "har_response")
			for _, r := range bodyRefs {
				if !seen[r.ID] {
					seen[r.ID] = true
					refs = append(refs, r)
				}
			}
		}
	}

	return refs
}

func extractFromJSONMap(data []byte, rawURL, route string, loc ObjectLocation, ownerPrincipal, ownerTenant, source string) []ObjectReference {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}

	var refs []ObjectReference
	for k, v := range m {
		strVal := fmt.Sprintf("%v", v)
		if IsContextualObjectID(k, strVal, loc, route) {
			kind := "string"
			if integerRegex.MatchString(strVal) {
				kind = "integer"
			} else if uuidRegex.MatchString(strVal) {
				kind = "uuid"
			}

			refs = append(refs, ObjectReference{
				ID:             generateRefID(loc, route, k, strVal),
				ObjectID:       strVal,
				Kind:           kind,
				Location:       loc,
				ParamName:      k,
				ObjectType:     InferObjectType(k, route),
				RouteTemplate:  route,
				TargetURL:      rawURL,
				Method:         "GET",
				OwnerPrincipal: ownerPrincipal,
				OwnerTenant:    ownerTenant,
				Source:         source,
				DiscoveredAt:   time.Now(),
			})
		}
	}
	return refs
}

func generateRefID(loc ObjectLocation, route, param, val string) string {
	cleanRoute := strings.TrimSpace(route)
	cleanParam := strings.TrimSpace(param)
	cleanVal := strings.TrimSpace(val)
	return fmt.Sprintf("%s:%s:%s=%s", loc, cleanRoute, cleanParam, cleanVal)
}
