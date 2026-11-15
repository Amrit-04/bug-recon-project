package endpoints

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/scoutr/scoutr/internal/scope"
)

// Inventory manages a thread-safe, deduplicated catalog of application endpoints with provenance.
type Inventory struct {
	mu        sync.RWMutex
	endpoints map[string]*Endpoint
}

// NewInventory creates an empty initialized Inventory.
func NewInventory() *Inventory {
	return &Inventory{
		endpoints: make(map[string]*Endpoint),
	}
}

// AddOrMerge inserts a new endpoint or merges attributes into an existing matching route.
func (inv *Inventory) AddOrMerge(ep *Endpoint) {
	if ep == nil || ep.NormalizedRoute == "" {
		return
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()

	// Normalize methods: default to GET if none provided
	if len(ep.Methods) == 0 {
		ep.Methods = []string{"GET"}
	}

	for _, method := range ep.Methods {
		key := ep.Key(method)
		existing, found := inv.endpoints[key]
		if !found {
			// Deep copy slice fields
			clone := &Endpoint{
				URL:              ep.URL,
				NormalizedRoute:  ep.NormalizedRoute,
				Methods:          []string{strings.ToUpper(method)},
				QueryParams:      uniqueStrings(ep.QueryParams),
				BodyFields:       uniqueStrings(ep.BodyFields),
				ContentTypes:     uniqueStrings(ep.ContentTypes),
				AuthRequired:     ep.AuthRequired,
				AuthType:         ep.AuthType,
				TechFingerprints: uniqueStrings(ep.TechFingerprints),
				Sources:          uniqueStrings(ep.Sources),
				Classifications:  uniqueClassifications(ep.Classifications),
				ResponseMetadata: ep.ResponseMetadata,
				DiscoveredAt:     ep.DiscoveredAt,
			}
			if clone.DiscoveredAt.IsZero() {
				clone.DiscoveredAt = time.Now()
			}
			if len(clone.Classifications) == 0 {
				clone.Classifications = ClassifyEndpoint(clone.NormalizedRoute, clone.QueryParams, clone.BodyFields, clone.ContentTypes)
			}
			inv.endpoints[key] = clone
		} else {
			// Merge attributes while preserving provenance
			existing.QueryParams = mergeUnique(existing.QueryParams, ep.QueryParams)
			existing.BodyFields = mergeUnique(existing.BodyFields, ep.BodyFields)
			existing.ContentTypes = mergeUnique(existing.ContentTypes, ep.ContentTypes)
			existing.TechFingerprints = mergeUnique(existing.TechFingerprints, ep.TechFingerprints)
			existing.Sources = mergeUnique(existing.Sources, ep.Sources)

			// Merge classifications
			existing.Classifications = mergeClassifications(existing.Classifications, ep.Classifications)
			if len(existing.Classifications) == 0 {
				existing.Classifications = ClassifyEndpoint(existing.NormalizedRoute, existing.QueryParams, existing.BodyFields, existing.ContentTypes)
			}

			// Update metadata if newly provided
			if existing.ResponseMetadata == nil && ep.ResponseMetadata != nil {
				existing.ResponseMetadata = ep.ResponseMetadata
			} else if existing.ResponseMetadata != nil && ep.ResponseMetadata != nil {
				if ep.ResponseMetadata.StatusCode != 0 {
					existing.ResponseMetadata.StatusCode = ep.ResponseMetadata.StatusCode
				}
				if ep.ResponseMetadata.ContentType != "" {
					existing.ResponseMetadata.ContentType = ep.ResponseMetadata.ContentType
				}
			}

			if ep.AuthRequired {
				existing.AuthRequired = true
				if ep.AuthType != "" {
					existing.AuthType = ep.AuthType
				}
			}
		}
	}
}

// AddRawURL normalizes a raw URL string, infers parameter keys, and adds it to inventory.
func (inv *Inventory) AddRawURL(rawURL, method, source string, tech []string) (*Endpoint, []ObjectIDCandidate) {
	canonicalURL, route, params, candidates := NormalizeURL(rawURL)
	if route == "" {
		return nil, nil
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	ep := &Endpoint{
		URL:              canonicalURL,
		NormalizedRoute:  route,
		Methods:          []string{method},
		QueryParams:      params,
		Sources:          []string{source},
		TechFingerprints: tech,
		DiscoveredAt:     time.Now(),
	}

	inv.AddOrMerge(ep)
	return ep, candidates
}

// GetAll returns a sorted slice of all endpoints in the inventory.
func (inv *Inventory) GetAll() []*Endpoint {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	out := make([]*Endpoint, 0, len(inv.endpoints))
	for _, ep := range inv.endpoints {
		out = append(out, ep)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].NormalizedRoute == out[j].NormalizedRoute {
			mI := ""
			if len(out[i].Methods) > 0 {
				mI = out[i].Methods[0]
			}
			mJ := ""
			if len(out[j].Methods) > 0 {
				mJ = out[j].Methods[0]
			}
			return mI < mJ
		}
		return out[i].NormalizedRoute < out[j].NormalizedRoute
	})

	return out
}

// GetByClassification returns all endpoints carrying the specified function tag.
func (inv *Inventory) GetByClassification(c FunctionClassification) []*Endpoint {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	var matched []*Endpoint
	for _, ep := range inv.endpoints {
		for _, tag := range ep.Classifications {
			if tag == c {
				matched = append(matched, ep)
				break
			}
		}
	}
	return matched
}

// FilterInScope filters the inventory in-place, removing any endpoints outside the provided scope.
func (inv *Inventory) FilterInScope(s *scope.Scope) {
	if s == nil {
		return
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()

	for key, ep := range inv.endpoints {
		if !s.IsURLInScope(ep.URL) {
			delete(inv.endpoints, key)
		}
	}
}

// Count returns the number of unique endpoint records.
func (inv *Inventory) Count() int {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return len(inv.endpoints)
}

// ToJSON exports all endpoints as formatted JSON bytes.
func (inv *Inventory) ToJSON() ([]byte, error) {
	all := inv.GetAll()
	return json.MarshalIndent(all, "", "  ")
}

// FromJSON loads endpoints from JSON bytes into the inventory.
func (inv *Inventory) FromJSON(data []byte) error {
	var list []*Endpoint
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("unmarshal endpoints: %w", err)
	}

	for _, ep := range list {
		inv.AddOrMerge(ep)
	}
	return nil
}

// Helper utility functions

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func mergeUnique(a, b []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range a {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func uniqueClassifications(in []FunctionClassification) []FunctionClassification {
	seen := make(map[FunctionClassification]bool)
	var out []FunctionClassification
	for _, c := range in {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func mergeClassifications(a, b []FunctionClassification) []FunctionClassification {
	seen := make(map[FunctionClassification]bool)
	var out []FunctionClassification
	for _, c := range a {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
