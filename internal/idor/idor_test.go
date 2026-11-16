package idor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/scope"
)

func TestIsContextualObjectID(t *testing.T) {
	tests := []struct {
		paramName string
		val       string
		loc       ObjectLocation
		route     string
		expected  bool
	}{
		// True positives
		{"user_id", "1024", LocationQuery, "/api/v1/profile", true},
		{"doc_uuid", "123e4567-e89b-12d3-a456-426614174000", LocationQuery, "/documents", true},
		{"id", "99", LocationPath, "/api/users/{id}", true},
		{"account_id", "act_555", LocationQuery, "/billing", true},
		{"invoice_id", "4040", LocationQuery, "/invoices", true},

		// True negatives (Pagination, statuses, transient, tokens)
		{"page", "2", LocationQuery, "/items", false},
		{"limit", "50", LocationQuery, "/items", false},
		{"offset", "100", LocationQuery, "/items", false},
		{"per_page", "25", LocationQuery, "/items", false},
		{"status", "200", LocationQuery, "/logs", false},
		{"code", "404", LocationQuery, "/errors", false},
		{"v", "1", LocationQuery, "/api", false},
		{"token", "secret123", LocationQuery, "/auth", false},
		{"jwt", "eyJ...", LocationQuery, "/auth", false},
		{"debug", "true", LocationQuery, "/test", false},
		{"q", "search_term", LocationQuery, "/search", false},
		{"timestamp", "1710000000", LocationQuery, "/metrics", false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s=%s", tc.paramName, tc.val), func(t *testing.T) {
			got := IsContextualObjectID(tc.paramName, tc.val, tc.loc, tc.route)
			if got != tc.expected {
				t.Errorf("IsContextualObjectID(%s, %s) = %v, expected %v", tc.paramName, tc.val, got, tc.expected)
			}
		})
	}
}

func TestObjectInventoryManagement(t *testing.T) {
	inv := NewObjectInventory()

	ref1 := ObjectReference{
		ObjectID:       "101",
		Kind:           "integer",
		Location:       LocationPath,
		ParamName:      "user_id",
		RouteTemplate:  "/api/users/{id}",
		TargetURL:      "https://api.example.com/api/users/101",
		OwnerPrincipal: "alice",
		OwnerTenant:    "tenant_1",
		Source:         "test",
	}

	ref2 := ObjectReference{
		ObjectID:       "102",
		Kind:           "integer",
		Location:       LocationPath,
		ParamName:      "user_id",
		RouteTemplate:  "/api/users/{id}",
		TargetURL:      "https://api.example.com/api/users/102",
		OwnerPrincipal: "bob",
		OwnerTenant:    "tenant_2",
		Source:         "test",
	}

	inv.Add(ref1)
	inv.Add(ref2)

	if inv.Count() != 2 {
		t.Fatalf("expected 2 items, got %d", inv.Count())
	}

	aliceRefs := inv.GetByOwner("alice")
	if len(aliceRefs) != 1 || aliceRefs[0].ObjectID != "101" {
		t.Errorf("unexpected alice refs: %+v", aliceRefs)
	}

	routeRefs := inv.GetByRoute("/api/users/{id}")
	if len(routeRefs) != 2 {
		t.Errorf("expected 2 route refs, got %d", len(routeRefs))
	}

	// Test AssociateOwner
	updated := inv.AssociateOwner("101", "alice_updated", "tenant_updated")
	if updated != 1 {
		t.Errorf("expected 1 updated owner, got %d", updated)
	}
	if inv.GetByOwner("alice_updated")[0].OwnerTenant != "tenant_updated" {
		t.Errorf("expected updated tenant")
	}

	// Test SaveJSON & LoadJSON
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "objects.json")
	if err := inv.SaveJSON(filePath); err != nil {
		t.Fatalf("SaveJSON failed: %v", err)
	}

	inv2 := NewObjectInventory()
	if err := inv2.LoadJSON(filePath); err != nil {
		t.Fatalf("LoadJSON failed: %v", err)
	}
	if inv2.Count() != 2 {
		t.Errorf("expected 2 items after LoadJSON, got %d", inv2.Count())
	}
}

func TestIngestEndpoints(t *testing.T) {
	epInv := endpoints.NewInventory()

	ep := &endpoints.Endpoint{
		Origin:          "https://api.example.com",
		URL:             "https://api.example.com/api/documents/500?version=1",
		NormalizedRoute: "/api/documents/{id}",
		Methods:         []string{"GET"},
		ObservedObjects: []endpoints.ObjectIDCandidate{
			{Type: "path", Name: "document_id", Value: "500", Kind: "integer"},
		},
		AuthObservations: []endpoints.AuthObservation{
			{Status: endpoints.AuthStatusAuthenticated, PrincipalLabel: "alice", TenantLabel: "org_a"},
		},
	}
	epInv.AddOrMerge(ep)

	objInv := NewObjectInventory()
	count := objInv.IngestEndpoints(epInv)

	if count != 1 || objInv.Count() != 1 {
		t.Fatalf("expected 1 candidate ingested, got %d", count)
	}

	all := objInv.GetAll()
	if all[0].ObjectID != "500" || all[0].OwnerPrincipal != "alice" || all[0].OwnerTenant != "org_a" {
		t.Errorf("unexpected candidate attributes: %+v", all[0])
	}
}

// Local mock test application covering all 7 vulnerability scenarios
func setupMockApp(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// 1. Correctly protected object (/api/v1/documents/101)
	// Alice (tenant_alpha) gets 200. Bob (tenant_beta) gets 403. Anon gets 401.
	mux.HandleFunc("/api/v1/documents/101", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 101, "title": "Alice's Secret Doc", "owner": "alice"}`))
			return
		}
		if authHeader == "Bearer token_bob" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "forbidden"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	// 2. Deliberately vulnerable cross-tenant IDOR (/api/v1/documents/102)
	// Alice gets 200. Bob gets 200 (UNAUTHORIZED DISCLOSURE!). Anon gets 401.
	mux.HandleFunc("/api/v1/documents/102", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice" || authHeader == "Bearer token_bob" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 102, "title": "Financial Report", "owner": "alice", "balance": 99999}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	// 3. Public object (/api/v1/documents/103)
	// Anyone gets 200 OK.
	mux.HandleFunc("/api/v1/documents/103", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 103, "title": "Terms of Service", "public": true}`))
	})

	// 4. Shared intra-tenant object (/api/v1/documents/104)
	// Alice (tenant_shared) and Charlie (tenant_shared) both get 200. Anon gets 401.
	mux.HandleFunc("/api/v1/documents/104", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice_shared" || authHeader == "Bearer token_charlie_shared" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 104, "title": "Shared Team Board", "tenant": "tenant_shared"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	// 4b. Private document in same tenant (/api/v1/documents/104_private)
	// Leaks Alice's private salary to anyone with tenant_shared token
	mux.HandleFunc("/api/v1/documents/104_private", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice_shared" || authHeader == "Bearer token_charlie_shared" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 1041, "title": "Alice Private Compensation", "owner": "alice", "salary": 185000}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	// 4c. Role-restricted document in same tenant (/api/v1/documents/104_admin)
	// Admin-only document accessed by member
	mux.HandleFunc("/api/v1/documents/104_admin", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice_admin" || authHeader == "Bearer token_charlie_member" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 1042, "title": "Admin Secrets", "secret": "internal_ops_token_999"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	// 4d. Explicitly shared document with specific users (/api/v1/documents/104_explicit)
	mux.HandleFunc("/api/v1/documents/104_explicit", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice_shared" || authHeader == "Bearer token_charlie_shared" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 1043, "title": "Explicit Project Collaboration", "collaborators": ["alice", "charlie"]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	// 5. Expired authentication session (/api/v1/documents/105)
	// Returns 401 Unauthorized with token expired message.
	mux.HandleFunc("/api/v1/documents/105", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "token expired"}`))
	})

	// 6. Cross-domain out-of-scope redirect (/api/v1/documents/106)
	// Attempts redirecting to an unauthorized domain.
	mux.HandleFunc("/api/v1/documents/106", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil-unauthorized-host.com/stolen", http.StatusFound)
	})

	// 7. Cross-instance document (/api/v1/documents/107_instance)
	// Belongs to US instance, but EU instance user can access it
	mux.HandleFunc("/api/v1/documents/107_instance", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice_us" || authHeader == "Bearer token_eve_eu" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 107, "title": "US Cluster Secret Database Config", "owner": "alice", "instance": "cluster_us", "private_key": "rsa_priv_key_data"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	// 8. Web Cache Deception leaking private data via cached response (/api/v1/documents/108_cached)
	mux.HandleFunc("/api/v1/documents/108_cached", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Age", "145")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": 108, "title": "Cached Confidential Medical File", "owner": "alice", "ssn": "000-11-2222"}`))
	})

	// 8b. Generic cached response without private object data (/api/v1/documents/108_generic_cache)
	mux.HandleFunc("/api/v1/documents/108_generic_cache", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Age", "300")
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok", "message": "cached public system notice"}`))
	})

	// 9. Cross-instance non-sensitive document (/api/v1/documents/107_nonsensitive)
	mux.HandleFunc("/api/v1/documents/107_nonsensitive", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer token_alice_us" || authHeader == "Bearer token_eve_eu" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id": 1071, "title": "Cluster Schedule Calendar", "owner": "alice"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "unauthorized"}`))
	})

	return httptest.NewServer(mux)
}

func TestDifferentialAuthorizationScenarios(t *testing.T) {
	server := setupMockApp(t)
	defer server.Close()

	sc := scope.New([]string{"127.0.0.1", "localhost"}, nil)
	client := httpx.New(httpx.Config{
		Scope:       sc,
		Timeout:     2 * time.Second,
		MaxBodySize: 1024 * 1024,
		GlobalRate:  50,
		PerHostRate: 50,
	})

	engine := NewCompareEngine(client)
	ctx := context.Background()

	// Profiles
	userAlice := auth.NewProfile("alice", "tenant_alpha", "bearer")
	userAlice.SetHeader("Authorization", "Bearer token_alice")

	userBob := auth.NewProfile("bob", "tenant_beta", "bearer")
	userBob.SetHeader("Authorization", "Bearer token_bob")

	// Scenario 1: Correctly protected object (/api/v1/documents/101)
	t.Run("Scenario 1: Correctly Protected Object", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_101",
			ObjectID:       "101",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/101",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
		}

		comp, err := engine.CompareCandidate(ctx, ref, userAlice, userBob)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if comp.OwnerStatus != 200 || comp.TesterStatus != 403 || comp.AnonStatus != 401 {
			t.Errorf("unexpected statuses: Owner=%d, Tester=%d, Anon=%d", comp.OwnerStatus, comp.TesterStatus, comp.AnonStatus)
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusCandidate || finding != nil {
			t.Errorf("expected Candidate without finding, got status %s", status)
		}
	})

	// Scenario 2: Deliberately vulnerable cross-tenant IDOR (/api/v1/documents/102)
	t.Run("Scenario 2: Vulnerable Cross-Tenant IDOR", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_102",
			ObjectID:       "102",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/102",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
		}

		comp, err := engine.CompareCandidate(ctx, ref, userAlice, userBob)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if comp.OwnerStatus != 200 || comp.TesterStatus != 200 || comp.AnonStatus != 401 {
			t.Errorf("unexpected statuses: Owner=%d, Tester=%d, Anon=%d", comp.OwnerStatus, comp.TesterStatus, comp.AnonStatus)
		}

		if !comp.IsDisclosed {
			t.Errorf("expected IsDisclosed=true")
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusCrossTenant || finding == nil {
			t.Fatalf("expected CrossTenant IDOR with finding, got %s", status)
		}

		if finding.Severity != findings.SeverityHigh {
			t.Errorf("expected High severity for cross-tenant IDOR, got %s", finding.Severity)
		}
		if !strings.Contains(finding.Title, "Cross-Tenant") {
			t.Errorf("expected Cross-Tenant in title: %s", finding.Title)
		}
		if len(finding.References) == 0 {
			t.Errorf("expected references in finding")
		}
	})

	// Scenario 3: Public object (/api/v1/documents/103)
	t.Run("Scenario 3: Public Object Detected", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_103",
			ObjectID:       "103",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/103",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
		}

		comp, err := engine.CompareCandidate(ctx, ref, userAlice, userBob)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if !comp.IsPublicResource {
			t.Errorf("expected IsPublicResource=true for public endpoint")
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusNeedsReview || finding != nil {
			t.Errorf("public resource should not produce an IDOR finding: status=%s, finding=%v", status, finding)
		}
	})

	// Scenario 4: Intentionally shared intra-tenant object (/api/v1/documents/104)
	t.Run("Scenario 4: Intentionally Shared Intra-Tenant Object", func(t *testing.T) {
		aliceShared := auth.NewProfile("alice", "tenant_shared", "bearer")
		aliceShared.SetHeader("Authorization", "Bearer token_alice_shared")

		charlieShared := auth.NewProfile("charlie", "tenant_shared", "bearer")
		charlieShared.SetHeader("Authorization", "Bearer token_charlie_shared")

		ref := ObjectReference{
			ID:             "ref_104",
			ObjectID:       "104",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/104",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_shared",
			AccessPolicy:   AccessPolicyTenantShared,
		}

		comp, err := engine.CompareCandidate(ctx, ref, aliceShared, charlieShared)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if !comp.IsAuthorizedShare {
			t.Errorf("expected IsAuthorizedShare=true for tenant_shared policy")
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusAuthorizedShare || finding != nil {
			t.Fatalf("expected AuthorizedShare without finding, got status %s", status)
		}
	})

	// Scenario 5: Unauthorized private document in same tenant (/api/v1/documents/104_private)
	t.Run("Scenario 5: Unauthorized Private Document Same Tenant", func(t *testing.T) {
		aliceShared := auth.NewProfile("alice", "tenant_shared", "bearer")
		aliceShared.SetHeader("Authorization", "Bearer token_alice_shared")

		charlieShared := auth.NewProfile("charlie", "tenant_shared", "bearer")
		charlieShared.SetHeader("Authorization", "Bearer token_charlie_shared")

		ref := ObjectReference{
			ID:             "ref_104_priv",
			ObjectID:       "1041",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/104_private",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_shared",
			AccessPolicy:   AccessPolicyPrivate,
		}

		comp, err := engine.CompareCandidate(ctx, ref, aliceShared, charlieShared)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if !comp.IsSharedOrSameTenant {
			t.Errorf("expected IsSharedOrSameTenant=true")
		}
		if !comp.IsDisclosed {
			t.Errorf("expected IsDisclosed=true for disclosed salary field")
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusSameTenantUnauthorized || finding == nil {
			t.Fatalf("expected SameTenantUnauthorized with finding, got %s", status)
		}
		if finding.Severity != findings.SeverityMedium {
			t.Errorf("expected Medium severity for same-tenant unauthorized access, got %s", finding.Severity)
		}
		if !strings.Contains(finding.Title, "Intra-Tenant") {
			t.Errorf("expected Intra-Tenant in title: %s", finding.Title)
		}
	})

	// Scenario 6: Role-restricted document in same tenant (/api/v1/documents/104_admin)
	t.Run("Scenario 6: Role-Restricted Document In Same Tenant", func(t *testing.T) {
		aliceAdmin := auth.NewProfile("alice", "tenant_shared", "bearer")
		aliceAdmin.SetHeader("Authorization", "Bearer token_alice_admin")
		aliceAdmin.SetRole("admin")

		charlieMember := auth.NewProfile("charlie", "tenant_shared", "bearer")
		charlieMember.SetHeader("Authorization", "Bearer token_charlie_member")
		charlieMember.SetRole("member")

		ref := ObjectReference{
			ID:             "ref_104_adm",
			ObjectID:       "1042",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/104_admin",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_shared",
			OwnerRole:      "admin",
			AccessPolicy:   AccessPolicyRoleRestricted,
			AllowedRoles:   []string{"admin"},
		}

		comp, err := engine.CompareCandidate(ctx, ref, aliceAdmin, charlieMember)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusUnauthorizedRole || finding == nil {
			t.Fatalf("expected UnauthorizedRole for role violation, got %s", status)
		}
		if finding.RuleID != "IDOR-ROLE-001" {
			t.Errorf("expected IDOR-ROLE-001 rule, got %s", finding.RuleID)
		}
		if finding.Severity != findings.SeverityHigh {
			t.Errorf("expected High severity for privilege escalation, got %s", finding.Severity)
		}
	})

	// Scenario 7: Explicit resource-level access permission (/api/v1/documents/104_explicit)
	t.Run("Scenario 7: Explicit Resource-Level Access Permission", func(t *testing.T) {
		aliceShared := auth.NewProfile("alice", "tenant_shared", "bearer")
		aliceShared.SetHeader("Authorization", "Bearer token_alice_shared")

		charlieShared := auth.NewProfile("charlie", "tenant_shared", "bearer")
		charlieShared.SetHeader("Authorization", "Bearer token_charlie_shared")

		ref := ObjectReference{
			ID:             "ref_104_exp",
			ObjectID:       "1043",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/104_explicit",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_shared",
			AccessPolicy:   AccessPolicyPrivate,
			AllowedUsers:   []string{"alice", "charlie"}, // explicitly allowed
		}

		comp, err := engine.CompareCandidate(ctx, ref, aliceShared, charlieShared)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if !comp.IsAuthorizedShare {
			t.Errorf("expected IsAuthorizedShare=true for explicitly allowed user")
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusAuthorizedShare || finding != nil {
			t.Fatalf("expected AuthorizedShare without finding, got status %s", status)
		}
	})

	// Scenario 8: Cross-instance IDOR (/api/v1/documents/107_instance)
	t.Run("Scenario 8: Vulnerable Cross-Instance IDOR", func(t *testing.T) {
		aliceUS := auth.NewProfile("alice", "tenant_alpha", "bearer")
		aliceUS.SetHeader("Authorization", "Bearer token_alice_us")
		aliceUS.SetInstance("cluster_us")

		eveEU := auth.NewProfile("eve", "tenant_alpha", "bearer")
		eveEU.SetHeader("Authorization", "Bearer token_eve_eu")
		eveEU.SetInstance("cluster_eu")

		ref := ObjectReference{
			ID:             "ref_107",
			ObjectID:       "107",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/107_instance",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
			OwnerInstance:  "cluster_us",
			AccessPolicy:   AccessPolicyPrivate,
		}

		comp, err := engine.CompareCandidate(ctx, ref, aliceUS, eveEU)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if comp.Boundary != BoundaryCrossInstance {
			t.Fatalf("expected BoundaryCrossInstance, got %s", comp.Boundary)
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusCrossInstance || finding == nil {
			t.Fatalf("expected CrossInstance IDOR with finding, got %s", status)
		}
		if finding.Severity != findings.SeverityCritical {
			t.Errorf("expected Critical severity for cross-instance IDOR, got %s", finding.Severity)
		}
		if !strings.Contains(finding.Title, "Cross-Instance") {
			t.Errorf("expected Cross-Instance in title: %s", finding.Title)
		}
	})

	// Scenario 9: Web Cache Deception (/api/v1/documents/108_cached)
	t.Run("Scenario 9: Web Cache Deception Private Leakage", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_108",
			ObjectID:       "108",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/108_cached",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
			AccessPolicy:   AccessPolicyPrivate,
		}

		comp, err := engine.CompareCandidate(ctx, ref, userAlice, userBob)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if !comp.WasCached || !comp.IsCacheDeception {
			t.Errorf("expected WasCached=true and IsCacheDeception=true (wasCached=%v, isCacheDecept=%v)", comp.WasCached, comp.IsCacheDeception)
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusCacheDeception || finding == nil {
			t.Fatalf("expected CacheDeception status with finding, got %s", status)
		}
		if finding.RuleID != "CACHE-DECEPT-001" {
			t.Errorf("expected CACHE-DECEPT-001 rule, got %s", finding.RuleID)
		}
		if finding.Severity != findings.SeverityHigh {
			t.Errorf("expected High severity for cache deception, got %s", finding.Severity)
		}
		if !strings.Contains(finding.Title, "Web Cache Deception") {
			t.Errorf("expected Web Cache Deception in title: %s", finding.Title)
		}
	})

	// Scenario 10: Authentication isolation & credential masquerade prevention
	t.Run("Scenario 10: Credential Masquerade Prevention", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_101",
			ObjectID:       "101",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/101",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
		}

		// Both profiles with identical bearer token
		twin1 := auth.NewProfile("twin1", "tenant_alpha", "bearer")
		twin1.SetHeader("Authorization", "Bearer shared_token")

		twin2 := auth.NewProfile("twin2", "tenant_beta", "bearer")
		twin2.SetHeader("Authorization", "Bearer shared_token")

		_, err := engine.CompareCandidate(ctx, ref, twin1, twin2)
		if err == nil || !strings.Contains(err.Error(), "identical") {
			t.Errorf("expected error rejecting identical credentials, got: %v", err)
		}
	})

	// Scenario 11: Expired authentication session (/api/v1/documents/105)
	t.Run("Scenario 11: Expired Authentication Session", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_105",
			ObjectID:       "105",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/105",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
		}

		comp, err := engine.CompareCandidate(ctx, ref, userAlice, userBob)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		if comp.OwnerStatus != 401 {
			t.Errorf("expected 401 for expired owner session, got %d", comp.OwnerStatus)
		}
		if comp.Status != IDORStatusCandidate {
			t.Errorf("expected Candidate status when baseline fails")
		}
	})

	// Scenario 12: Cross-domain out-of-scope redirect blocked (/api/v1/documents/106)
	t.Run("Scenario 12: Cross-Domain Out-of-Scope Redirect Blocked", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_106",
			ObjectID:       "106",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/106",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
		}

		comp, err := engine.CompareCandidate(ctx, ref, userAlice, userBob)
		if err != nil {
			t.Fatalf("CompareCandidate error: %v", err)
		}

		// Owner access should fail because redirect to evil-unauthorized-host.com is blocked by scope!
		if comp.OwnerStatus == 200 {
			t.Errorf("out-of-scope redirect should not result in 200 OK")
		}
		if comp.Status != IDORStatusCandidate {
			t.Errorf("expected Candidate status when out-of-scope redirect is blocked")
		}
	})

	// Scenario 8b: Calibrated Cross-Instance IDOR Severity (Non-sensitive object -> High severity, not blind Critical)
	t.Run("Scenario 8b: Calibrated Cross-Instance IDOR Severity", func(t *testing.T) {
		aliceUS := auth.NewProfile("alice", "tenant_alpha", "bearer")
		aliceUS.SetHeader("Authorization", "Bearer token_alice_us")
		aliceUS.SetInstance("cluster_us")

		eveEU := auth.NewProfile("eve", "tenant_alpha", "bearer")
		eveEU.SetHeader("Authorization", "Bearer token_eve_eu")
		eveEU.SetInstance("cluster_eu")

		ref := ObjectReference{
			ID:             "ref_107_calib",
			ObjectID:       "1071",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/107_nonsensitive",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
			OwnerInstance:  "cluster_us",
			AccessPolicy:   AccessPolicyPrivate,
		}

		comp, err := engine.CompareCandidate(ctx, ref, aliceUS, eveEU)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusCrossInstance || finding == nil {
			t.Fatalf("expected CrossInstance IDOR with finding, got %s", status)
		}
		// Without sensitive fields, severity should be calibrated to High rather than blindly Critical
		if finding.Severity != findings.SeverityHigh {
			t.Errorf("expected calibrated High severity for non-sensitive cross-instance IDOR, got %s", finding.Severity)
		}
	})

	// Scenario 9b: Cache headers alone without private object disclosure do not produce an IDOR finding
	t.Run("Scenario 9b: Cache Headers Alone Do Not Produce IDOR Finding", func(t *testing.T) {
		ref := ObjectReference{
			ID:             "ref_108_generic",
			ObjectID:       "1082",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/108_generic_cache",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_alpha",
			AccessPolicy:   AccessPolicyPrivate,
		}

		comp, err := engine.CompareCandidate(ctx, ref, userAlice, userBob)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusNeedsReview || finding != nil {
			t.Errorf("expected NeedsReview without finding when cache headers exist but no private object is disclosed, got status %s, finding: %v", status, finding)
		}
	})

	// Scenario 13: Unknown Access Policy produces NeedsReview candidate
	t.Run("Scenario 13: Unknown Access Policy Requires Manual Review", func(t *testing.T) {
		aliceShared := auth.NewProfile("alice", "tenant_shared", "bearer")
		aliceShared.SetHeader("Authorization", "Bearer token_alice_shared")

		charlieShared := auth.NewProfile("charlie", "tenant_shared", "bearer")
		charlieShared.SetHeader("Authorization", "Bearer token_charlie_shared")

		ref := ObjectReference{
			ID:             "ref_104_unknown",
			ObjectID:       "104",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/104",
			OwnerPrincipal: "alice",
			OwnerTenant:    "tenant_shared",
			AccessPolicy:   AccessPolicyUnknown, // explicitly unknown policy
		}

		comp, err := engine.CompareCandidate(ctx, ref, aliceShared, charlieShared)
		if err != nil {
			t.Fatalf("CompareCandidate failed: %v", err)
		}

		status, finding, _ := ValidateComparison(comp)
		if status != IDORStatusNeedsReview || finding != nil {
			t.Fatalf("expected NeedsReview without finding for unknown policy, got status %s", status)
		}
	})

	// Scenario 14: Same-User Access Aborted
	t.Run("Scenario 14: Same-User Access Aborted", func(t *testing.T) {
		alice1 := auth.NewProfile("alice_session_1", "tenant_alpha", "bearer")
		alice1.SetHeader("Authorization", "Bearer token_session_1")
		alice1.SetVerifiedIdentity("user_same_999", "tenant_alpha", "member")

		alice2 := auth.NewProfile("alice_session_2", "tenant_alpha", "bearer")
		alice2.SetHeader("Authorization", "Bearer token_session_2")
		alice2.SetVerifiedIdentity("user_same_999", "tenant_alpha", "member")

		ref := ObjectReference{
			ID:             "ref_101_same",
			ObjectID:       "101",
			Location:       LocationPath,
			ParamName:      "doc_id",
			RouteTemplate:  "/api/v1/documents/{id}",
			TargetURL:      server.URL + "/api/v1/documents/101",
			OwnerPrincipal: "alice_session_1",
			OwnerTenant:    "tenant_alpha",
			AccessPolicy:   AccessPolicyPrivate,
		}

		_, err := engine.CompareCandidate(ctx, ref, alice1, alice2)
		if err == nil || !strings.Contains(err.Error(), "same verified user ID") {
			t.Errorf("expected error rejecting same verified user identity, got: %v", err)
		}
	})

	// Scenario 14b: ValidateComparison handles IDORStatusSameUser safely without finding
	t.Run("Scenario 14b: ValidateComparison SameUser Handling", func(t *testing.T) {
		comp := &ComparisonResult{
			Status: IDORStatusSameUser,
		}
		status, finding, err := ValidateComparison(comp)
		if err != nil || status != IDORStatusSameUser || finding != nil {
			t.Errorf("expected Safe SameUser status without finding, got status %s, finding: %v, err: %v", status, finding, err)
		}
	})
}

func TestGenerateIDORReportMarkdown(t *testing.T) {
	comp := &ComparisonResult{
		Candidate: ObjectReference{
			RouteTemplate: "/api/v1/documents/{id}",
			ObjectID:      "102",
		},
		OwnerStatus:   200,
		TesterStatus:  200,
		AnonStatus:    401,
		Status:        IDORStatusConfirmed,
		EvidenceNotes: "Confirmed IDOR",
	}

	finding := &findings.Finding{
		Title:       "Cross-Tenant IDOR",
		Severity:    findings.SeverityHigh,
		Target:      "https://example.com/api/v1/documents/102",
		Path:        "/api/v1/documents/{id}",
		Impact:      "Data leak",
		Evidence:    "Tested",
		Response:    "HTTP/1.1 200 OK",
		Remediation: "Fix access control",
	}

	report := GenerateIDORReportMarkdown([]*ComparisonResult{comp}, []*findings.Finding{finding})
	if !strings.Contains(report, "Scoutr IDOR Research & Validation Report") {
		t.Errorf("missing header in report")
	}
	if !strings.Contains(report, "Cross-Tenant IDOR") {
		t.Errorf("missing finding in report")
	}
	if !strings.Contains(report, "/api/v1/documents/{id}") {
		t.Errorf("missing route in comparison matrix")
	}
}

func TestCanonicalizeBody(t *testing.T) {
	jsonBody := []byte(`{
		"id": 42,
		"name": "Report",
		"timestamp": "2026-11-15T12:00:00Z",
		"request_id": "req-9999",
		"csrf": "token123"
	}`)

	canon := CanonicalizeBody(jsonBody, "application/json")
	canonStr := string(canon)

	if strings.Contains(canonStr, "req-9999") || strings.Contains(canonStr, "token123") {
		t.Errorf("volatile fields not stripped: %s", canonStr)
	}
	if !strings.Contains(canonStr, "Report") || !strings.Contains(canonStr, "42") {
		t.Errorf("essential fields dropped: %s", canonStr)
	}
}

func TestIngestHARAndResponseObjects(t *testing.T) {
	entries := []*auth.ImportedHAREntry{
		{
			Method: "GET",
			URL:    "https://api.example.com/api/users/999/profile",
			QueryParams: map[string]string{
				"account_id": "act_888",
			},
			ResponseBody: `{"id": 999, "document_id": "doc_777", "name": "Test User"}`,
			Timestamp:    time.Now(),
		},
	}

	inv := NewObjectInventory()
	count := inv.IngestHAR(entries, "har_owner", "har_tenant")

	if count == 0 || inv.Count() == 0 {
		t.Fatalf("expected candidates ingested from HAR, got %d", count)
	}

	ownerRefs := inv.GetByOwner("har_owner")
	if len(ownerRefs) == 0 {
		t.Fatalf("expected owner refs for har_owner")
	}

	foundDoc := false
	foundAcc := false
	for _, r := range ownerRefs {
		if r.ObjectID == "doc_777" {
			foundDoc = true
		}
		if r.ObjectID == "act_888" {
			foundAcc = true
		}
	}
	if !foundDoc || !foundAcc {
		t.Errorf("missing expected candidates doc_777 or act_888: %+v", ownerRefs)
	}
}
