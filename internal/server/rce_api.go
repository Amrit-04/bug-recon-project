package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/rce"
	"github.com/scoutr/scoutr/internal/workspace"
)

// handleRunRCE routes `/api/runs/{id}/rce/...` requests.
func (s *Server) handleRunRCE(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, parts []string) {
	if len(parts) < 3 {
		http.Error(w, "invalid RCE sub-path", http.StatusBadRequest)
		return
	}

	action := parts[2]
	switch action {
	case "overview":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRCEOverview(w, r, ws)

	case "candidates":
		if len(parts) >= 4 {
			cid := parts[3]
			if r.Method == http.MethodGet {
				s.handleGetRCECandidate(w, r, ws, cid)
				return
			}
			if r.Method == http.MethodPut || r.Method == http.MethodPost {
				s.handleUpdateRCECandidate(w, r, ws, cid)
				return
			}
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			s.handleListRCECandidates(w, r, ws)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

	case "discover":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRCEDiscover(w, r, ws)

	case "advisories":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRCEAdvisories(w, r, ws)

	case "validate":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRCEValidate(w, r, ws)

	case "report":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRCEReport(w, r, ws)

	default:
		http.Error(w, fmt.Sprintf("unknown RCE action: %s", action), http.StatusNotFound)
	}
}

func (s *Server) handleRCEOverview(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var candidates []*rce.RCECandidate
	_ = ws.LoadArtifact(workspace.RCECandidatesFile, &candidates)

	overview := rce.RCEOverview{
		TotalCandidates:      len(candidates),
		CategoryDistribution: make(map[rce.RCECategory]int),
		RecentActivity:       []string{},
	}

	for _, c := range candidates {
		overview.CategoryDistribution[c.Category]++
		if c.PriorityScore >= 70 {
			overview.HighPriorityCount++
		}
		if len(c.MatchingAdvisories) > 0 {
			overview.AdvisoryMatchCount++
		}
		switch c.ValidationStatus {
		case rce.StatusValidated:
			overview.ValidatedCount++
		case rce.StatusCorroborated:
			overview.CorroboratedCount++
		case rce.StatusCandidate, rce.StatusDiscovered:
			overview.AwaitingValidation++
		}

		for _, att := range c.ValidationAttempts {
			overview.RecentActivity = append(overview.RecentActivity,
				fmt.Sprintf("[%s] %s on %s: ExecutionConfirmed=%t",
					att.Timestamp.Format("15:04:05"), att.Profile, c.Route, att.ExecutionConfirmed))
		}
	}

	if len(overview.RecentActivity) > 10 {
		overview.RecentActivity = overview.RecentActivity[len(overview.RecentActivity)-10:]
	}

	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleListRCECandidates(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var candidates []*rce.RCECandidate
	_ = ws.LoadArtifact(workspace.RCECandidatesFile, &candidates)

	q := r.URL.Query()
	catFilter := strings.ToLower(strings.TrimSpace(q.Get("category")))
	statusFilter := strings.ToLower(strings.TrimSpace(q.Get("status")))
	searchFilter := strings.ToLower(strings.TrimSpace(q.Get("search")))
	techFilter := strings.ToLower(strings.TrimSpace(q.Get("tech")))
	minPriority, _ := strconv.Atoi(q.Get("min_priority"))

	var filtered []*rce.RCECandidate
	for _, c := range candidates {
		if c == nil {
			continue
		}
		if catFilter != "" && strings.ToLower(string(c.Category)) != catFilter {
			continue
		}
		if statusFilter != "" && strings.ToLower(string(c.ValidationStatus)) != statusFilter {
			continue
		}
		if minPriority > 0 && c.PriorityScore < minPriority {
			continue
		}
		if techFilter != "" {
			matchedTech := false
			for _, t := range c.RelevantTech {
				if strings.Contains(strings.ToLower(t), techFilter) {
					matchedTech = true
					break
				}
			}
			if !matchedTech {
				continue
			}
		}
		if searchFilter != "" {
			fullText := strings.ToLower(c.Route + " " + c.FeatureType + " " + c.Hypothesis + " " + c.SuspectedSink)
			if !strings.Contains(fullText, searchFilter) {
				continue
			}
		}

		filtered = append(filtered, c)
	}

	if filtered == nil {
		filtered = []*rce.RCECandidate{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(filtered),
		"candidates": filtered,
	})
}

func (s *Server) handleGetRCECandidate(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, cid string) {
	var candidates []*rce.RCECandidate
	_ = ws.LoadArtifact(workspace.RCECandidatesFile, &candidates)

	for _, c := range candidates {
		if c != nil && c.ID == cid {
			writeJSON(w, http.StatusOK, c)
			return
		}
	}

	http.Error(w, fmt.Sprintf("candidate '%s' not found", cid), http.StatusNotFound)
}

func (s *Server) handleUpdateRCECandidate(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, cid string) {
	var payload struct {
		Status rce.ValidationStatus `json:"status"`
		Notes  string               `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	var candidates []*rce.RCECandidate
	if err := ws.LoadArtifact(workspace.RCECandidatesFile, &candidates); err != nil {
		http.Error(w, fmt.Sprintf("load candidates: %v", err), http.StatusInternalServerError)
		return
	}

	var updated *rce.RCECandidate
	for _, c := range candidates {
		if c != nil && c.ID == cid {
			if payload.Status != "" {
				c.ValidationStatus = payload.Status
			}
			if payload.Notes != "" {
				c.ResearcherNotes = payload.Notes
			}
			c.UpdatedAt = time.Now()
			updated = c
			break
		}
	}

	if updated == nil {
		http.Error(w, fmt.Sprintf("candidate '%s' not found", cid), http.StatusNotFound)
		return
	}

	if err := ws.SaveArtifact(workspace.RCECandidatesFile, candidates); err != nil {
		http.Error(w, fmt.Sprintf("save candidates: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleRCEDiscover(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	target := filepath.Base(ws.Dir)
	if idx := strings.Index(target, "-"); idx != -1 {
		target = target[:idx]
	}

	job, err := s.jobs.Submit(JobTypeRCEDiscover, filepath.Base(ws.Dir), target, nil,
		func(ctx context.Context, j *Job, update func(int, string, string, int), emitLog func(string)) error {
			update(0, "loading", "Loading endpoints and classifying RCE attack surfaces...", 20)
			emitLog("Starting RCE attack surface discovery from endpoint inventory")

			var epList []*endpoints.Endpoint
			if err := ws.LoadArtifact(workspace.EndpointsFile, &epList); err != nil {
				return fmt.Errorf("load endpoints: %w", err)
			}

			// 1. Attack surface classification
			classifier := rce.NewClassifier()
			candidates := classifier.ClassifyEndpoints(target, epList)
			emitLog(fmt.Sprintf("Identified %d potential execution pathways", len(candidates)))

			// 2. Correlate multi-step processing chains
			update(1, "correlating", "Detecting multi-step processing chains...", 45)
			detector := rce.NewChainDetector()
			detector.CorrelateChains(candidates)

			// 3. Correlate public CVE intelligence
			update(2, "advisories", "Correlating public CVE advisories & version ranges...", 65)
			registry := rce.NewAdvisoryRegistry()
			for _, cand := range candidates {
				matches := registry.CorrelateCandidate(cand)
				if len(matches) > 0 {
					cand.MatchingAdvisories = matches
					emitLog(fmt.Sprintf("Correlated %d advisories for %s", len(matches), cand.Route))
				}
			}

			// 4. Calculate deterministic prioritization scores
			update(3, "prioritizing", "Calculating deterministic research priority scores...", 85)
			prioritizer := rce.NewPrioritizer()
			prioritizer.PrioritizeCandidates(candidates)

			// Save candidates artifact
			if err := ws.SaveArtifact(workspace.RCECandidatesFile, candidates); err != nil {
				return fmt.Errorf("save rce_candidates.json: %w", err)
			}

			emitLog(fmt.Sprintf("Saved %d prioritized RCE candidates to workspace", len(candidates)))
			update(4, "completed", fmt.Sprintf("RCE discovery complete: %d attack surface candidates identified", len(candidates)), 100)
			return nil
		})

	if err != nil {
		http.Error(w, fmt.Sprintf("submit job: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleRCEAdvisories(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	registry := rce.NewAdvisoryRegistry()
	advisories := registry.GetAllAdvisories()

	var candidates []*rce.RCECandidate
	_ = ws.LoadArtifact(workspace.RCECandidatesFile, &candidates)

	// Map reachability across candidates
	type AdvisoryView struct {
		Advisory       rce.Advisory `json:"advisory"`
		MatchCount     int          `json:"match_count"`
		HighestTier    string       `json:"highest_tier"`
		ReachableRoute string       `json:"reachable_route,omitempty"`
	}

	var results []AdvisoryView
	for _, adv := range advisories {
		view := AdvisoryView{
			Advisory:    adv,
			HighestTier: "none",
		}
		for _, c := range candidates {
			for _, m := range c.MatchingAdvisories {
				if m.Advisory.ID == adv.ID {
					view.MatchCount++
					view.HighestTier = string(m.ProgressionTier)
					if m.ProgressionTier == rce.TierComponentReachable {
						view.ReachableRoute = c.Route
					}
				}
			}
		}
		results = append(results, view)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(results),
		"advisories": results,
	})
}

func (s *Server) handleRCEValidate(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var payload struct {
		CandidateID string                `json:"candidate_id"`
		Profile     rce.ValidationProfile `json:"profile"`
		AuthLabel   string                `json:"auth_label,omitempty"`
		CallbackURL string                `json:"callback_url,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	if payload.CandidateID == "" {
		http.Error(w, "candidate_id is required", http.StatusBadRequest)
		return
	}
	if payload.Profile == "" {
		payload.Profile = rce.ProfileSafeActive
	}

	target := filepath.Base(ws.Dir)
	if idx := strings.Index(target, "-"); idx != -1 {
		target = target[:idx]
	}

	job, err := s.jobs.Submit(JobTypeRCEValidate, filepath.Base(ws.Dir), target, nil,
		func(ctx context.Context, j *Job, update func(int, string, string, int), emitLog func(string)) error {
			update(0, "initializing", fmt.Sprintf("Preparing %s validation for candidate %s...", payload.Profile, payload.CandidateID), 15)
			emitLog(fmt.Sprintf("Starting RCE validation check for %s under profile %s", payload.CandidateID, payload.Profile))

			var candidates []*rce.RCECandidate
			if err := ws.LoadArtifact(workspace.RCECandidatesFile, &candidates); err != nil {
				return fmt.Errorf("load candidates: %w", err)
			}

			var targetCand *rce.RCECandidate
			for _, c := range candidates {
				if c != nil && c.ID == payload.CandidateID {
					targetCand = c
					break
				}
			}
			if targetCand == nil {
				return fmt.Errorf("candidate '%s' not found", payload.CandidateID)
			}

			// Load auth profile if requested
			var authProf *auth.Profile
			if payload.AuthLabel != "" {
				profilesPath := filepath.Join(ws.Dir, "auth_profiles.json")
				if profiles, err := auth.LoadProfiles(profilesPath); err == nil {
					for _, p := range profiles {
						if strings.EqualFold(p.PrincipalLabel, payload.AuthLabel) {
							authProf = p
							emitLog(fmt.Sprintf("Attached authenticated session for principal '%s'", p.PrincipalLabel))
							break
						}
					}
				}
			}

			sc := s.getScopeForWorkspace(ws)
			client := httpx.New(httpx.Config{
				Scope:   sc,
				Timeout: 10 * time.Second,
			})
			validator := rce.NewValidator(client, sc)

			update(1, "executing", "Dispatching controlled benign probes with negative controls...", 50)
			attempt, err := validator.ValidateCandidate(ctx, targetCand, payload.Profile, authProf, payload.CallbackURL)
			if err != nil {
				return fmt.Errorf("validation error: %w", err)
			}

			emitLog(fmt.Sprintf("Probe attempt completed: ExecutionConfirmed=%t, MarkerFound=%t, ReflectionExcluded=%t",
				attempt.ExecutionConfirmed, attempt.MarkerFound, attempt.ReflectionExcluded))

			// Save updated candidates
			update(2, "saving", "Recording structured validation evidence...", 85)
			if err := ws.SaveArtifact(workspace.RCECandidatesFile, candidates); err != nil {
				return fmt.Errorf("save updated candidates: %w", err)
			}

			statusMsg := fmt.Sprintf("Validation complete. Status: %s. %s", targetCand.ValidationStatus, attempt.Notes)
			update(3, "completed", statusMsg, 100)
			emitLog(statusMsg)
			return nil
		})

	if err != nil {
		http.Error(w, fmt.Sprintf("submit job: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleRCEReport(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var candidates []*rce.RCECandidate
	_ = ws.LoadArtifact(workspace.RCECandidatesFile, &candidates)

	registry := rce.NewAdvisoryRegistry()
	advisories := registry.GetAllAdvisories()

	reportMD := rce.GenerateReport(ws.Target, s.cfg.ScopeFile, candidates, advisories)

	if r.URL.Query().Get("format") == "raw" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(reportMD))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"markdown": reportMD,
	})
}
