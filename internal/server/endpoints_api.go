package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/workspace"
)

// handleRunEndpoints handles `/api/runs/{id}/endpoints` requests.
func (s *Server) handleRunEndpoints(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace, parts []string) {
	if len(parts) >= 3 && parts[2] == "queue" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleQueueEndpoints(w, r, ws)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Load endpoints from workspace
	var list []*endpoints.Endpoint
	if err := ws.LoadArtifact(workspace.EndpointsFile, &list); err != nil {
		// Return empty list if artifact doesn't exist yet
		writeJSON(w, http.StatusOK, map[string]any{
			"total":     0,
			"endpoints": []*endpoints.Endpoint{},
		})
		return
	}

	q := r.URL.Query()
	hostFilter := strings.ToLower(strings.TrimSpace(q.Get("host")))
	routeFilter := strings.ToLower(strings.TrimSpace(q.Get("route")))
	methodFilter := strings.ToUpper(strings.TrimSpace(q.Get("method")))
	techFilter := strings.ToLower(strings.TrimSpace(q.Get("tech")))
	authFilter := strings.ToLower(strings.TrimSpace(q.Get("auth")))
	classFilter := strings.ToLower(strings.TrimSpace(q.Get("classification")))
	paramFilter := strings.ToLower(strings.TrimSpace(q.Get("param")))
	priorityFilter := strings.ToLower(strings.TrimSpace(q.Get("priority")))
	searchFilter := strings.ToLower(strings.TrimSpace(q.Get("search")))

	var filtered []*endpoints.Endpoint
	for _, ep := range list {
		if ep == nil {
			continue
		}

		// Host filter
		if hostFilter != "" {
			u, err := url.Parse(ep.URL)
			if err != nil || !strings.Contains(strings.ToLower(u.Host), hostFilter) {
				continue
			}
		}

		// Route filter
		if routeFilter != "" {
			if !strings.Contains(strings.ToLower(ep.NormalizedRoute), routeFilter) &&
				!strings.Contains(strings.ToLower(ep.URL), routeFilter) {
				continue
			}
		}

		// Method filter
		if methodFilter != "" {
			methodMatches := false
			for _, m := range ep.Methods {
				if strings.ToUpper(m) == methodFilter {
					methodMatches = true
					break
				}
			}
			if !methodMatches {
				continue
			}
		}

		// Tech filter
		if techFilter != "" {
			hasTech := false
			for _, t := range ep.TechFingerprints {
				if strings.Contains(strings.ToLower(t), techFilter) {
					hasTech = true
					break
				}
			}
			if !hasTech {
				continue
			}
		}

		// Auth filter
		if authFilter != "" {
			authMatches := false
			for _, obs := range ep.AuthObservations {
				if strings.EqualFold(string(obs.Status), authFilter) {
					authMatches = true
					break
				}
			}
			if !authMatches {
				continue
			}
		}

		// Classification filter
		if classFilter != "" {
			hasClass := false
			for _, c := range ep.Classifications {
				if strings.EqualFold(string(c.Category), classFilter) {
					hasClass = true
					break
				}
			}
			if !hasClass {
				continue
			}
		}

		// Param filter
		if paramFilter != "" {
			hasParam := false
			for _, p := range ep.QueryParams {
				if strings.Contains(strings.ToLower(p), paramFilter) {
					hasParam = true
					break
				}
			}
			if !hasParam {
				for _, p := range ep.BodyFields {
					if strings.Contains(strings.ToLower(p), paramFilter) {
						hasParam = true
						break
					}
				}
			}
			if !hasParam {
				continue
			}
		}

		// Priority filter
		if priorityFilter != "" {
			hasPrio := false
			for _, c := range ep.Classifications {
				prioStr := fmt.Sprintf("%d", c.Priority)
				if strings.EqualFold(prioStr, priorityFilter) || strings.EqualFold("p"+prioStr, priorityFilter) {
					hasPrio = true
					break
				}
			}
			if !hasPrio {
				continue
			}
		}

		// Search filter
		if searchFilter != "" {
			matches := strings.Contains(strings.ToLower(ep.URL), searchFilter) ||
				strings.Contains(strings.ToLower(ep.NormalizedRoute), searchFilter)
			if !matches {
				for _, m := range ep.Methods {
					if strings.Contains(strings.ToLower(m), searchFilter) {
						matches = true
						break
					}
				}
			}
			if !matches {
				for _, p := range ep.QueryParams {
					if strings.Contains(strings.ToLower(p), searchFilter) {
						matches = true
						break
					}
				}
			}
			if !matches {
				for _, c := range ep.Classifications {
					if strings.Contains(strings.ToLower(string(c.Category)), searchFilter) {
						matches = true
						break
					}
				}
			}
			if !matches {
				continue
			}
		}

		filtered = append(filtered, ep)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":     len(filtered),
		"endpoints": filtered,
	})
}

// QueueEndpointsRequest defines payload for queuing specific endpoints.
type QueueEndpointsRequest struct {
	EndpointIDs []string `json:"endpoint_ids"`
	Engine      string   `json:"engine"` // "idor", "rce"
}

func (s *Server) handleQueueEndpoints(w http.ResponseWriter, r *http.Request, ws *workspace.Workspace) {
	var req QueueEndpointsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
		return
	}

	if len(req.EndpointIDs) == 0 {
		http.Error(w, "endpoint_ids list cannot be empty", http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"queued": len(req.EndpointIDs),
		"engine": req.Engine,
		"status": "queued",
	})
}
