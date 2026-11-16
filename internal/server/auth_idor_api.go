package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/idor"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/validate"
	"github.com/scoutr/scoutr/internal/workspace"
)

func getProfilesPath(ws *workspace.Workspace) string {
	p1 := filepath.Join(ws.Dir, "auth_secrets.json")
	if _, err := os.Stat(p1); err == nil {
		return p1
	}
	p2 := filepath.Join(ws.Dir, "auth_profiles.json")
	if _, err := os.Stat(p2); err == nil {
		return p2
	}
	return p1
}

func loadProfilesFromWorkspace(ws *workspace.Workspace) ([]*auth.Profile, error) {
	path := getProfilesPath(ws)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []*auth.Profile{}, nil
	}
	return auth.LoadProfiles(path)
}

func saveProfilesToWorkspace(ws *workspace.Workspace, profiles []*auth.Profile) error {
	p1 := filepath.Join(ws.Dir, "auth_secrets.json")
	if err := auth.SaveProfiles(p1, profiles); err != nil {
		return err
	}

	// Save only redacted summaries to auth_profiles.json to eliminate plaintext secret duplication
	var summaries []auth.ProfileSummary
	for _, p := range profiles {
		if p != nil {
			summaries = append(summaries, p.RedactedSummary())
		}
	}
	data, err := json.MarshalIndent(summaries, "", "  ")
	if err == nil {
		p2 := filepath.Join(ws.Dir, "auth_profiles.json")
		_ = os.WriteFile(p2, data, 0644)
	}
	return nil
}

// handleRunAuth routes `/api/runs/{id}/auth/...` requests.
func (s *Server) handleRunAuth(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, parts []string) {
	if len(parts) < 3 {
		http.Error(w, "invalid auth sub-path", http.StatusBadRequest)
		return
	}

	action := parts[2]
	switch action {
	case "profiles":
		if len(parts) >= 4 && parts[3] == "verify" {
			s.handleVerifyProfile(w, r, ws)
			return
		}
		if r.Method == http.MethodGet {
			s.handleListProfiles(w, r, ws)
			return
		}
		if r.Method == http.MethodPost {
			s.handleSaveProfile(w, r, ws)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

	case "har":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleHARUpload(w, r, ws)

	default:
		http.Error(w, fmt.Sprintf("unknown auth action: %s", action), http.StatusNotFound)
	}
}

// handleListProfiles returns safe ProfileSummary structs with raw credentials masked.
func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	profiles, err := loadProfilesFromWorkspace(ws)
	if err != nil {
		http.Error(w, fmt.Sprintf("load profiles: %v", err), http.StatusInternalServerError)
		return
	}

	summaries := make([]auth.ProfileSummary, 0, len(profiles))
	for _, p := range profiles {
		if p != nil {
			summaries = append(summaries, p.RedactedSummary())
		}
	}

	writeJSON(w, http.StatusOK, summaries)
}

// SaveProfileRequest defines the API payload for creating or updating an auth profile.
type SaveProfileRequest struct {
	PrincipalLabel   string            `json:"principal_label"`
	TenantLabel      string            `json:"tenant_label"`
	InstanceLabel    string            `json:"instance_label,omitempty"`
	RoleLabel        string            `json:"role_label,omitempty"`
	AuthType         string            `json:"auth_type"` // "bearer", "cookie", "custom"
	IdentityEndpoint string            `json:"identity_endpoint,omitempty"`
	Token            string            `json:"token,omitempty"` // convenience Bearer token
	Headers          map[string]string `json:"headers,omitempty"`
	Cookies          []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"cookies,omitempty"`
}

func (s *Server) handleSaveProfile(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var req SaveProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	principal := strings.TrimSpace(req.PrincipalLabel)
	if principal == "" {
		http.Error(w, "principal_label is required", http.StatusBadRequest)
		return
	}
	tenant := strings.TrimSpace(req.TenantLabel)
	if tenant == "" {
		tenant = "default"
	}
	instance := strings.TrimSpace(req.InstanceLabel)
	if instance == "" {
		instance = "default"
	}
	role := strings.TrimSpace(req.RoleLabel)
	if role == "" {
		role = "member"
	}
	authType := strings.TrimSpace(req.AuthType)
	if authType == "" {
		authType = "bearer"
	}

	profiles, _ := loadProfilesFromWorkspace(ws)

	// Look for existing profile with this principal label or create new
	var target *auth.Profile
	for _, p := range profiles {
		if strings.EqualFold(p.PrincipalLabel, principal) {
			target = p
			break
		}
	}

	if target == nil {
		target = auth.NewProfile(principal, tenant, authType)
		profiles = append(profiles, target)
	}

	target.PrincipalLabel = principal
	target.TenantLabel = tenant
	target.InstanceLabel = instance
	target.RoleLabel = role
	target.AuthType = authType
	target.IdentityEndpoint = strings.TrimSpace(req.IdentityEndpoint)
	target.IdentityStatus = "unverified"

	if req.Headers != nil {
		for k, v := range req.Headers {
			if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
				target.SetHeader(k, v)
			}
		}
	}
	if req.Token != "" {
		tokenVal := strings.TrimSpace(req.Token)
		if !strings.HasPrefix(strings.ToLower(tokenVal), "bearer ") {
			tokenVal = "Bearer " + tokenVal
		}
		target.SetHeader("Authorization", tokenVal)
	}

	if len(req.Cookies) > 0 {
		target.Cookies = nil
		for _, c := range req.Cookies {
			if strings.TrimSpace(c.Name) != "" {
				target.AddCookie(&http.Cookie{
					Name:  strings.TrimSpace(c.Name),
					Value: strings.TrimSpace(c.Value),
				})
			}
		}
	}

	if err := saveProfilesToWorkspace(ws, profiles); err != nil {
		http.Error(w, fmt.Sprintf("save profiles: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, target.RedactedSummary())
}

// VerifyProfileRequest defines input for verifying identity endpoint.
type VerifyProfileRequest struct {
	PrincipalLabel   string `json:"principal_label"`
	IdentityEndpoint string `json:"identity_endpoint,omitempty"`
}

func (s *Server) handleVerifyProfile(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	profiles, err := loadProfilesFromWorkspace(ws)
	if err != nil || len(profiles) == 0 {
		http.Error(w, "no profiles found in workspace", http.StatusNotFound)
		return
	}

	var target *auth.Profile
	for _, p := range profiles {
		if strings.EqualFold(p.PrincipalLabel, req.PrincipalLabel) {
			target = p
			break
		}
	}
	if target == nil {
		http.Error(w, fmt.Sprintf("profile '%s' not found", req.PrincipalLabel), http.StatusNotFound)
		return
	}

	if req.IdentityEndpoint != "" {
		target.IdentityEndpoint = strings.TrimSpace(req.IdentityEndpoint)
	}

	if target.IdentityEndpoint == "" {
		http.Error(w, "identity_endpoint is not configured on this profile", http.StatusBadRequest)
		return
	}

	// Build scope-enforcing client
	sc := s.getScopeForWorkspace(ws)
	client := httpx.New(httpx.Config{
		Scope:   sc,
		Timeout: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	vErr := target.VerifyIdentity(ctx, client)
	_ = saveProfilesToWorkspace(ws, profiles)

	resp := map[string]any{
		"principal_label":   target.PrincipalLabel,
		"identity_endpoint": target.IdentityEndpoint,
		"identity_status":   target.IdentityStatus,
		"verified_id":       target.VerifiedID,
		"verified_tenant":   target.VerifiedTenant,
		"verified_role":     target.VerifiedRole,
	}
	if vErr != nil {
		resp["error"] = vErr.Error()
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHARUpload(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	// Limit request body to 10MB
	r.Body = http.MaxBytesReader(w, r.Body, auth.MaxHARSizeBytes)

	var harBytes []byte

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		err := r.ParseMultipartForm(auth.MaxHARSizeBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("parse multipart form: %v", err), http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("har")
		if err != nil {
			http.Error(w, fmt.Sprintf("read form file 'har': %v", err), http.StatusBadRequest)
			return
		}
		defer file.Close()
		harBytes, err = io.ReadAll(file)
		if err != nil {
			http.Error(w, fmt.Sprintf("read HAR bytes: %v", err), http.StatusBadRequest)
			return
		}
	} else {
		var err error
		harBytes, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("read request body: %v", err), http.StatusBadRequest)
			return
		}
	}

	if len(harBytes) == 0 {
		http.Error(w, "empty HAR payload", http.StatusBadRequest)
		return
	}

	sc := s.getScopeForWorkspace(ws)

	// Import HAR with scope filtering and credential redaction
	importedEntries, err := auth.ImportHAR(harBytes, sc, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("import HAR: %v", err), http.StatusBadRequest)
		return
	}

	// 1. Ingest endpoints
	inv := endpoints.NewInventory()
	var existingEndpoints []*endpoints.Endpoint
	_ = ws.LoadArtifact(workspace.EndpointsFile, &existingEndpoints)
	for _, ep := range existingEndpoints {
		inv.AddOrMerge(ep)
	}

	endpointsAdded := 0
	for _, entry := range importedEntries {
		if entry.URL == "" {
			continue
		}
		u, err := url.Parse(entry.URL)
		if err != nil {
			continue
		}

		method := strings.ToUpper(entry.Method)
		if method == "" {
			method = "GET"
		}
		origin, canonicalURL, normalizedRoute, queryParams, candidates := endpoints.NormalizeURL(entry.URL)
		if origin == "" {
			origin = u.Scheme + "://" + u.Host
		}
		if canonicalURL == "" {
			canonicalURL = entry.URL
		}
		ep := &endpoints.Endpoint{
			Origin:          origin,
			URL:             canonicalURL,
			NormalizedRoute: normalizedRoute,
			Methods:         []string{method},
			QueryParams:     queryParams,
			ObservedObjects: candidates,
			Sources:         []string{"har_import"},
			DiscoveredAt:    entry.Timestamp,
		}
		ep.AuthObservations = append(ep.AuthObservations, endpoints.AuthObservation{
			Status:     endpoints.AuthStatusUnknown,
			Source:     "har_import",
			ObservedAt: entry.Timestamp,
		})
		inv.AddOrMerge(ep)
		endpointsAdded++

		if s.events != nil {
			s.events.Broadcast("", EventEndpointDiscovered, map[string]any{
				"url":    ep.URL,
				"method": method,
				"source": "har_import",
			})
		}
	}

	_ = ws.SaveArtifact(workspace.EndpointsFile, inv.GetAll())

	// 2. Ingest IDOR candidate objects
	objInv := idor.NewObjectInventory()
	candidatesPath := filepath.Join(ws.Dir, workspace.IDORCandidatesFile)
	_ = objInv.LoadJSON(candidatesPath)

	owner := r.URL.Query().Get("owner")
	if owner == "" {
		owner = "user_a"
	}
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		tenant = "tenant_1"
	}

	candidatesAdded := objInv.IngestHAR(importedEntries, owner, tenant)
	_ = objInv.SaveJSON(candidatesPath)

	if s.events != nil {
		s.events.Broadcast("", EventCandidateDiscovered, map[string]any{
			"count":  candidatesAdded,
			"source": "har_import",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":             "Successfully imported HAR capture",
		"entries_processed":   len(importedEntries),
		"endpoints_ingested":  endpointsAdded,
		"candidates_ingested": candidatesAdded,
	})
}

// handleRunIDOR routes `/api/runs/{id}/idor/...` requests.
func (s *Server) handleRunIDOR(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, parts []string) {
	if len(parts) < 3 {
		http.Error(w, "invalid IDOR sub-path", http.StatusBadRequest)
		return
	}

	action := parts[2]
	switch action {
	case "inventory":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleIDORInventory(w, r, ws)

	case "candidates":
		if len(parts) >= 5 && parts[4] == "policy" {
			if r.Method != http.MethodPut && r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			s.handleUpdateCandidatePolicy(w, r, ws, parts[3])
			return
		}
		if r.Method == http.MethodGet {
			s.handleListIDORCandidates(w, r, ws)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

	case "compare":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleIDORCompare(w, r, ws)

	case "comparisons":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListIDORComparisons(w, r, ws)

	case "report":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleIDORReport(w, r, ws)

	default:
		http.Error(w, fmt.Sprintf("unknown IDOR action: %s", action), http.StatusNotFound)
	}
}

func (s *Server) handleIDORInventory(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	target := filepath.Base(ws.Dir)
	if idx := strings.Index(target, "-"); idx != -1 {
		target = target[:idx]
	}

	job, err := s.jobs.Submit(JobTypeIDORInventory, filepath.Base(ws.Dir), target, nil,
		func(ctx context.Context, j *Job, update func(int, string, string, int), emitLog func(string)) error {
			update(0, "extracting", "Loading endpoints and extracting candidate object references...", 20)
			emitLog("Starting candidate object reference extraction from endpoints")

			var epList []*endpoints.Endpoint
			if err := ws.LoadArtifact(workspace.EndpointsFile, &epList); err != nil {
				return fmt.Errorf("load endpoints: %w", err)
			}

			objInv := idor.NewObjectInventory()
			candidatesPath := filepath.Join(ws.Dir, workspace.IDORCandidatesFile)
			_ = objInv.LoadJSON(candidatesPath)

			for _, ep := range epList {
				candidates := idor.ExtractCandidatesFromEndpoint(ep)
				objInv.AddAll(candidates)
			}

			update(1, "saving", fmt.Sprintf("Identified %d candidate object references", objInv.Count()), 80)
			emitLog(fmt.Sprintf("Identified %d candidate object references", objInv.Count()))

			if err := objInv.SaveJSON(candidatesPath); err != nil {
				return fmt.Errorf("save candidates: %w", err)
			}

			update(2, "completed", fmt.Sprintf("Successfully updated IDOR candidate inventory with %d objects", objInv.Count()), 100)
			return nil
		})

	if err != nil {
		http.Error(w, fmt.Sprintf("submit job: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleListIDORCandidates(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	objInv := idor.NewObjectInventory()
	candidatesPath := filepath.Join(ws.Dir, workspace.IDORCandidatesFile)
	_ = objInv.LoadJSON(candidatesPath)

	all := objInv.GetAll()
	q := r.URL.Query()
	locFilter := strings.ToLower(strings.TrimSpace(q.Get("location")))
	ownerFilter := strings.ToLower(strings.TrimSpace(q.Get("owner")))
	policyFilter := strings.ToLower(strings.TrimSpace(q.Get("policy")))
	searchFilter := strings.ToLower(strings.TrimSpace(q.Get("search")))

	var filtered []idor.ObjectReference
	for _, ref := range all {
		if locFilter != "" && strings.ToLower(string(ref.Location)) != locFilter {
			continue
		}
		if ownerFilter != "" && strings.ToLower(ref.OwnerPrincipal) != ownerFilter {
			continue
		}
		if policyFilter != "" && strings.ToLower(ref.AccessPolicy) != policyFilter {
			continue
		}
		if searchFilter != "" {
			matches := strings.Contains(strings.ToLower(ref.ObjectID), searchFilter) ||
				strings.Contains(strings.ToLower(ref.RouteTemplate), searchFilter) ||
				strings.Contains(strings.ToLower(ref.TargetURL), searchFilter) ||
				strings.Contains(strings.ToLower(ref.ParamName), searchFilter)
			if !matches {
				continue
			}
		}
		filtered = append(filtered, ref)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(filtered),
		"candidates": filtered,
	})
}

// UpdateCandidatePolicyRequest defines payload for updating object reference access policy.
type UpdateCandidatePolicyRequest struct {
	AccessPolicy string   `json:"access_policy"` // "private", "explicitly_shared", "public", "unknown"
	AllowedRoles []string `json:"allowed_roles,omitempty"`
	AllowedUsers []string `json:"allowed_users,omitempty"`
	UniqueMarker string   `json:"unique_marker,omitempty"`
}

func (s *Server) handleUpdateCandidatePolicy(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, candidateID string) {
	var req UpdateCandidatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	objInv := idor.NewObjectInventory()
	candidatesPath := filepath.Join(ws.Dir, workspace.IDORCandidatesFile)
	if err := objInv.LoadJSON(candidatesPath); err != nil {
		http.Error(w, "candidates artifact not found", http.StatusNotFound)
		return
	}

	all := objInv.GetAll()
	var matched *idor.ObjectReference
	for i := range all {
		if all[i].ID == candidateID {
			if req.AccessPolicy != "" {
				all[i].AccessPolicy = req.AccessPolicy
			}
			if len(req.AllowedRoles) > 0 {
				all[i].AllowedRoles = req.AllowedRoles
			}
			if len(req.AllowedUsers) > 0 {
				all[i].AllowedUsers = req.AllowedUsers
			}
			if req.UniqueMarker != "" {
				all[i].UniqueMarker = req.UniqueMarker
			}
			matched = &all[i]
			break
		}
	}

	if matched == nil {
		http.Error(w, fmt.Sprintf("candidate %s not found", candidateID), http.StatusNotFound)
		return
	}

	freshInv := idor.NewObjectInventory()
	freshInv.AddAll(all)
	_ = freshInv.SaveJSON(candidatesPath)

	writeJSON(w, http.StatusOK, matched)
}

// IDORCompareRequest defines parameters to start differential testing.
type IDORCompareRequest struct {
	UserALabel   string   `json:"user_a_label"`
	UserBLabel   string   `json:"user_b_label"`
	CandidateIDs []string `json:"candidate_ids,omitempty"`
}

func (s *Server) handleIDORCompare(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var req IDORCompareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	userA := strings.TrimSpace(req.UserALabel)
	if userA == "" {
		userA = "user_a"
	}
	userB := strings.TrimSpace(req.UserBLabel)
	if userB == "" {
		userB = "user_b"
	}

	target := filepath.Base(ws.Dir)
	if idx := strings.Index(target, "-"); idx != -1 {
		target = target[:idx]
	}

	config := map[string]any{
		"user_a":        userA,
		"user_b":        userB,
		"candidate_ids": req.CandidateIDs,
	}

	job, err := s.jobs.Submit(JobTypeIDORCompare, filepath.Base(ws.Dir), target, config,
		func(ctx context.Context, j *Job, update func(int, string, string, int), emitLog func(string)) error {
			update(0, "initializing", "Loading profiles and candidates...", 10)
			emitLog(fmt.Sprintf("Loading profiles for %s and %s", userA, userB))

			profiles, err := loadProfilesFromWorkspace(ws)
			if err != nil {
				return fmt.Errorf("load profiles: %w", err)
			}

			var profileA, profileB *auth.Profile
			for _, p := range profiles {
				if strings.EqualFold(p.PrincipalLabel, userA) {
					profileA = p
				}
				if strings.EqualFold(p.PrincipalLabel, userB) {
					profileB = p
				}
			}
			if profileA == nil {
				return fmt.Errorf("profile '%s' not found in workspace", userA)
			}
			if profileB == nil {
				return fmt.Errorf("profile '%s' not found in workspace", userB)
			}

			// Pre-flight check distinct credentials
			if err := auth.CheckDistinctCredentials(profileA, profileB); err != nil {
				return fmt.Errorf("credential isolation check failed: %w", err)
			}

			// Load candidates
			objInv := idor.NewObjectInventory()
			candidatesPath := filepath.Join(ws.Dir, workspace.IDORCandidatesFile)
			_ = objInv.LoadJSON(candidatesPath)
			allCandidates := objInv.GetAll()

			var toTest []idor.ObjectReference
			if len(req.CandidateIDs) > 0 {
				idMap := make(map[string]bool)
				for _, id := range req.CandidateIDs {
					idMap[id] = true
				}
				for _, c := range allCandidates {
					if idMap[c.ID] {
						toTest = append(toTest, c)
					}
				}
			} else {
				toTest = allCandidates
			}

			if len(toTest) == 0 {
				emitLog("No candidate object references available to test")
				update(1, "completed", "No candidates to test", 100)
				return nil
			}

			sc := s.getScopeForWorkspace(ws)
			client := httpx.New(httpx.Config{
				Scope:       sc,
				Timeout:     10 * time.Second,
				GlobalRate:  5,
				PerHostRate: 5,
			})
			engine := idor.NewCompareEngine(client)

			var comparisons []*idor.ComparisonResult
			var validatedList []*validate.ValidatedFinding
			_ = ws.LoadArtifact(workspace.ValidatedFindingsFile, &validatedList)

			emitLog(fmt.Sprintf("Executing differential tests on %d candidates...", len(toTest)))

			for i, cand := range toTest {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				pct := 10 + int(float64(i)/float64(len(toTest))*80)
				update(1, "testing", fmt.Sprintf("Testing candidate %d/%d: %s (%s)", i+1, len(toTest), cand.RouteTemplate, cand.ObjectID), pct)
				emitLog(fmt.Sprintf("[%d/%d] Comparing %s (%s)", i+1, len(toTest), cand.RouteTemplate, cand.ObjectID))

				res, err := engine.CompareCandidate(ctx, cand, profileA, profileB)
				if err != nil {
					emitLog(fmt.Sprintf("  Warning on %s: %v", cand.ID, err))
					continue
				}

				status, finding, _ := idor.ValidateComparison(res)
				res.Status = status
				comparisons = append(comparisons, res)

				if finding != nil {
					emitLog(fmt.Sprintf("  FOUND IDOR (%s): %s on %s", status, finding.Title, finding.Target))
					vf := &validate.ValidatedFinding{
						Finding: finding,
						Status:  validate.StatusVerified,
					}
					validatedList = append(validatedList, vf)

					if s.events != nil {
						s.events.Broadcast(j.ID, EventValidationResult, map[string]any{
							"status":       string(status),
							"finding_id":   finding.ID,
							"title":        finding.Title,
							"severity":     finding.Severity,
							"target":       finding.Target,
							"boundary":     res.Boundary,
							"gate_verdict": string(vf.Status),
						})
					}
				}
			}

			// Save comparisons artifact
			compPath := filepath.Join(ws.Dir, workspace.IDORComparisonsFile)
			data, err := json.MarshalIndent(comparisons, "", "  ")
			if err == nil {
				_ = os.WriteFile(compPath, data, 0644)
			}

			// Update validated findings if new findings were detected
			_ = ws.SaveValidatedFindings(validatedList)

			update(2, "completed", fmt.Sprintf("Differential testing completed: tested %d candidates, found %d confirmed findings", len(comparisons), len(validatedList)), 100)
			emitLog(fmt.Sprintf("IDOR differential testing completed. Total tested: %d", len(comparisons)))

			return nil
		})

	if err != nil {
		http.Error(w, fmt.Sprintf("submit job: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleListIDORComparisons(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	compPath := filepath.Join(ws.Dir, workspace.IDORComparisonsFile)
	data, err := os.ReadFile(compPath)
	if err != nil {
		writeJSON(w, http.StatusOK, []*idor.ComparisonResult{})
		return
	}

	var list []*idor.ComparisonResult
	if err := json.Unmarshal(data, &list); err != nil {
		writeJSON(w, http.StatusOK, []*idor.ComparisonResult{})
		return
	}

	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleIDORReport(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	compPath := filepath.Join(ws.Dir, workspace.IDORComparisonsFile)
	data, err := os.ReadFile(compPath)
	if err != nil {
		http.Error(w, "no IDOR comparisons found for this workspace", http.StatusNotFound)
		return
	}

	var list []*idor.ComparisonResult
	_ = json.Unmarshal(data, &list)

	var sb strings.Builder
	sb.WriteString("# Scoutr IDOR Research & Differential Testing Report\n\n")
	sb.WriteString(fmt.Sprintf("**Workspace:** `%s`  \n", filepath.Base(ws.Dir)))
	sb.WriteString(fmt.Sprintf("**Generated At:** %s  \n\n", time.Now().Format("2006-01-02 15:04:05 UTC")))

	confirmedCount := 0
	unauthRoleCount := 0
	sameTenantCount := 0
	needsReviewCount := 0

	for _, c := range list {
		switch c.Status {
		case idor.IDORStatusConfirmed, idor.IDORStatusCrossTenant, idor.IDORStatusCrossInstance:
			confirmedCount++
		case idor.IDORStatusUnauthorizedRole:
			unauthRoleCount++
		case idor.IDORStatusSameTenantUnauthorized:
			sameTenantCount++
		case idor.IDORStatusNeedsReview:
			needsReviewCount++
		}
	}

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Candidates Tested:** %d\n", len(list)))
	sb.WriteString(fmt.Sprintf("- **Confirmed Cross-Account IDOR:** %d\n", confirmedCount))
	sb.WriteString(fmt.Sprintf("- **Unauthorized Role Access:** %d\n", unauthRoleCount))
	sb.WriteString(fmt.Sprintf("- **Same-Tenant Unauthorized:** %d\n", sameTenantCount))
	sb.WriteString(fmt.Sprintf("- **Needs Manual Review:** %d\n\n", needsReviewCount))

	sb.WriteString("## Differential Comparison Matrix\n\n")
	sb.WriteString("| Candidate Route | Parameter | Object ID | Owner (A) | Tester (B) | Anon | Boundary | Verdict |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|\n")

	for _, c := range list {
		sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %d | %d | %d | %s | **%s** |\n",
			c.Candidate.RouteTemplate,
			c.Candidate.ParamName,
			c.Candidate.ObjectID,
			c.OwnerStatus,
			c.TesterStatus,
			c.AnonStatus,
			c.Boundary,
			c.Status,
		))
	}

	sb.WriteString("\n## Evidence & Detailed Disclosures\n\n")
	for i, c := range list {
		if c.Status == idor.IDORStatusConfirmed || c.Status == idor.IDORStatusCrossTenant || c.Status == idor.IDORStatusCrossInstance || c.Status == idor.IDORStatusUnauthorizedRole {
			sb.WriteString(fmt.Sprintf("### Finding %d: %s [%s]\n\n", i+1, c.Candidate.RouteTemplate, c.Status))
			sb.WriteString(fmt.Sprintf("- **Target URL:** `%s`\n", c.RequestURL))
			sb.WriteString(fmt.Sprintf("- **Method:** `%s`\n", c.Method))
			sb.WriteString(fmt.Sprintf("- **Boundary Level:** `%s`\n", c.Boundary))
			sb.WriteString(fmt.Sprintf("- **Owner Principal:** `%s` (Tenant: `%s`)\n", c.OwnerProfile.PrincipalLabel, c.OwnerProfile.TenantLabel))
			sb.WriteString(fmt.Sprintf("- **Tester Principal:** `%s` (Tenant: `%s`)\n", c.TesterProfile.PrincipalLabel, c.TesterProfile.TenantLabel))
			sb.WriteString(fmt.Sprintf("- **Notes:** %s\n\n", c.EvidenceNotes))

			if len(c.DisclosedSensitiveFields) > 0 {
				sb.WriteString(fmt.Sprintf("- **Disclosed Sensitive Fields:** `%s`\n\n", strings.Join(c.DisclosedSensitiveFields, ", ")))
			}

			if c.RedactedTesterResponse != "" {
				sb.WriteString("```json\n" + c.RedactedTesterResponse + "\n```\n\n")
			}
		}
	}

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sb.String()))
}

// Helper to load scope from file or workspace
func (s *Server) getScopeForWorkspace(ws *workspace.Workspace) *scope.Scope {
	if s.cfg.ScopeFile != "" {
		if sc, err := scope.LoadFromFile(s.cfg.ScopeFile); err == nil {
			return sc
		}
	}
	target := filepath.Base(ws.Dir)
	if idx := strings.Index(target, "-"); idx != -1 {
		target = target[:idx]
	}
	return scope.New([]string{target, "*." + target}, nil)
}
