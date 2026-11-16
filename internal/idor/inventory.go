package idor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
)

// AccessPolicy values defining expected resource sharing boundaries.
const (
	AccessPolicyPrivate          = "private"
	AccessPolicyTenantShared     = "tenant_shared"
	AccessPolicyRoleRestricted   = "role_restricted"
	AccessPolicyExplicitlyShared = "explicitly_shared"
	AccessPolicyPublic           = "public"
	AccessPolicyUnknown          = "unknown"
)

// ObjectReference represents a concrete object identifier and its associated ownership, instance, and policy context.
type ObjectReference struct {
	ID             string         `json:"id"`
	ObjectID       string         `json:"object_id"`
	Kind           string         `json:"kind"` // "integer", "uuid", "hash", "string"
	Location       ObjectLocation `json:"location"`
	ParamName      string         `json:"param_name"`
	ObjectType     string         `json:"object_type"` // e.g. "user", "document", "invoice"
	RouteTemplate  string         `json:"route_template"`
	TargetURL      string         `json:"target_url"`
	Method         string         `json:"method"`
	OwnerPrincipal string         `json:"owner_principal"`          // e.g. "user_a", "owner", or "unknown"
	OwnerTenant    string         `json:"owner_tenant"`             // e.g. "tenant_1", or "unknown"
	OwnerInstance  string         `json:"owner_instance,omitempty"` // e.g. "prod-us-1", "shard-b", or "default"
	OwnerRole      string         `json:"owner_role,omitempty"`     // e.g. "admin", "member"

	// Expected access policy: "private" (default), "tenant_shared", "role_restricted", "public"
	AccessPolicy string   `json:"access_policy,omitempty"`
	AllowedRoles []string `json:"allowed_roles,omitempty"`
	AllowedUsers []string `json:"allowed_users,omitempty"`
	UniqueMarker string   `json:"unique_marker,omitempty"` // Unique test-object marker string expected in owner response

	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// IsExpectedAuthorized checks whether an accessor with given principal, tenant, instance, and role
// is authorized to access this object under documented application policy.
func (ref *ObjectReference) IsExpectedAuthorized(principal, tenant, instance, role string) bool {
	// Unknown policies cannot be assumed authorized
	if ref.AccessPolicy == AccessPolicyUnknown || ref.AccessPolicy == "unknown" {
		return false
	}

	// Public objects are always authorized
	if ref.AccessPolicy == AccessPolicyPublic || ref.AccessPolicy == "public" {
		return true
	}

	// Owner always authorized
	if ref.OwnerPrincipal != "" && ref.OwnerPrincipal != "unknown" && ref.OwnerPrincipal == principal {
		return true
	}

	// Cross-instance access is never authorized unless public
	if ref.OwnerInstance != "" && instance != "" && ref.OwnerInstance != instance {
		return false
	}

	// Cross-tenant access is never authorized unless public
	if ref.OwnerTenant != "" && tenant != "" && ref.OwnerTenant != tenant {
		return false
	}

	// Explicit allowed user list
	for _, u := range ref.AllowedUsers {
		if u == principal {
			return true
		}
	}

	// Explicitly shared policy with allowed roles
	if ref.AccessPolicy == AccessPolicyExplicitlyShared || ref.AccessPolicy == "explicitly_shared" {
		for _, r := range ref.AllowedRoles {
			if r == role {
				return true
			}
		}
		return false
	}

	// Same tenant handling
	if ref.AccessPolicy == AccessPolicyTenantShared || ref.AccessPolicy == "tenant_shared" || ref.AccessPolicy == "shared" {
		return true
	}

	// Role-restricted within tenant
	if ref.AccessPolicy == AccessPolicyRoleRestricted || ref.AccessPolicy == "role_restricted" {
		for _, r := range ref.AllowedRoles {
			if r == role {
				return true
			}
		}
		return false
	}

	// Default policy is private to owner
	return false
}

// ObjectInventory manages candidate object references and their ownership mapping.
type ObjectInventory struct {
	mu      sync.RWMutex
	objects map[string]*ObjectReference
}

// NewObjectInventory creates an initialized ObjectInventory.
func NewObjectInventory() *ObjectInventory {
	return &ObjectInventory{
		objects: make(map[string]*ObjectReference),
	}
}

// Add inserts or updates an object reference.
func (inv *ObjectInventory) Add(ref ObjectReference) {
	if ref.ObjectID == "" {
		return
	}
	if ref.ID == "" {
		ref.ID = generateRefID(ref.Location, ref.RouteTemplate, ref.ParamName, ref.ObjectID)
	}
	if ref.OwnerInstance == "" {
		ref.OwnerInstance = "default"
	}
	if ref.AccessPolicy == "" {
		ref.AccessPolicy = "private"
	}
	if ref.DiscoveredAt.IsZero() {
		ref.DiscoveredAt = time.Now()
	}

	inv.mu.Lock()
	defer inv.mu.Unlock()

	existing, found := inv.objects[ref.ID]
	if !found {
		inv.objects[ref.ID] = &ref
	} else {
		// Update owner if existing was unknown and incoming has known owner
		if existing.OwnerPrincipal == "unknown" && ref.OwnerPrincipal != "unknown" {
			existing.OwnerPrincipal = ref.OwnerPrincipal
			existing.OwnerTenant = ref.OwnerTenant
			existing.OwnerInstance = ref.OwnerInstance
			existing.OwnerRole = ref.OwnerRole
		}
		if ref.AccessPolicy != "private" {
			existing.AccessPolicy = ref.AccessPolicy
		}
		if ref.UniqueMarker != "" {
			existing.UniqueMarker = ref.UniqueMarker
		}
		if len(ref.AllowedRoles) > 0 {
			existing.AllowedRoles = ref.AllowedRoles
		}
		if len(ref.AllowedUsers) > 0 {
			existing.AllowedUsers = ref.AllowedUsers
		}
	}
}

// AddAll inserts multiple object references.
func (inv *ObjectInventory) AddAll(refs []ObjectReference) {
	for _, r := range refs {
		inv.Add(r)
	}
}

// IngestEndpoints extracts object references from an endpoints.Inventory catalog.
func (inv *ObjectInventory) IngestEndpoints(endpointInv *endpoints.Inventory) int {
	if endpointInv == nil {
		return 0
	}

	count := 0
	allEndpoints := endpointInv.GetAll()
	for _, ep := range allEndpoints {
		candidates := ExtractCandidatesFromEndpoint(ep)
		for _, c := range candidates {
			inv.Add(c)
			count++
		}
	}
	return count
}

// IngestHAR extracts object references from imported HAR transactions with an associated owner.
func (inv *ObjectInventory) IngestHAR(entries []*auth.ImportedHAREntry, ownerPrincipal, ownerTenant string) int {
	candidates := ExtractCandidatesFromHAR(entries, ownerPrincipal, ownerTenant)
	for _, c := range candidates {
		inv.Add(c)
	}
	return len(candidates)
}

// AssociateOwner maps an object identifier to a specific owner principal, tenant, and instance.
func (inv *ObjectInventory) AssociateOwner(objectID, principal, tenant string) int {
	return inv.AssociateOwnerExtended(objectID, principal, tenant, "default", "member", "private", nil, "")
}

// AssociateOwnerExtended binds comprehensive identity, tenant, instance, and policy metadata to an object.
func (inv *ObjectInventory) AssociateOwnerExtended(objectID, principal, tenant, instance, role, policy string, allowedRoles []string, uniqueMarker string) int {
	inv.mu.Lock()
	defer inv.mu.Unlock()

	updated := 0
	for _, obj := range inv.objects {
		if obj.ObjectID == objectID {
			obj.OwnerPrincipal = principal
			obj.OwnerTenant = tenant
			if instance != "" {
				obj.OwnerInstance = instance
			}
			if role != "" {
				obj.OwnerRole = role
			}
			if policy != "" {
				obj.AccessPolicy = policy
			}
			if len(allowedRoles) > 0 {
				obj.AllowedRoles = allowedRoles
			}
			if uniqueMarker != "" {
				obj.UniqueMarker = uniqueMarker
			}
			updated++
		}
	}
	return updated
}

// GetAll returns all object references sorted deterministically by RouteTemplate and ObjectID.
func (inv *ObjectInventory) GetAll() []ObjectReference {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	out := make([]ObjectReference, 0, len(inv.objects))
	for _, obj := range inv.objects {
		out = append(out, *obj)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].RouteTemplate != out[j].RouteTemplate {
			return out[i].RouteTemplate < out[j].RouteTemplate
		}
		if out[i].ObjectID != out[j].ObjectID {
			return out[i].ObjectID < out[j].ObjectID
		}
		return out[i].ID < out[j].ID
	})

	return out
}

// GetByOwner returns object references owned by a specific principal.
func (inv *ObjectInventory) GetByOwner(principal string) []ObjectReference {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	var out []ObjectReference
	for _, obj := range inv.objects {
		if obj.OwnerPrincipal == principal {
			out = append(out, *obj)
		}
	}
	return out
}

// GetByRoute returns object references for a normalized route template.
func (inv *ObjectInventory) GetByRoute(route string) []ObjectReference {
	inv.mu.RLock()
	defer inv.mu.RUnlock()

	var out []ObjectReference
	for _, obj := range inv.objects {
		if obj.RouteTemplate == route {
			out = append(out, *obj)
		}
	}
	return out
}

// Count returns the number of distinct object references.
func (inv *ObjectInventory) Count() int {
	inv.mu.RLock()
	defer inv.mu.RUnlock()
	return len(inv.objects)
}

// SaveJSON writes the object inventory to a JSON file.
func (inv *ObjectInventory) SaveJSON(filePath string) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	all := inv.GetAll()
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal object inventory: %w", err)
	}

	return os.WriteFile(filePath, data, 0644)
}

// LoadJSON loads object references from a JSON file.
func (inv *ObjectInventory) LoadJSON(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read object inventory: %w", err)
	}

	var list []ObjectReference
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("unmarshal object inventory: %w", err)
	}

	inv.AddAll(list)
	return nil
}
