package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/rce"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	rceFromDir     string
	rceCandidateID string
	rceProfileName string
	rceAuthLabel   string
	rceOutputFile  string
	rceCallbackURL string
)

var rceCmd = &cobra.Command{
	Use:   "rce",
	Short: "Application-aware Remote Code Execution (RCE) attack surface research and validation",
	Long: `Advanced RCE research engine for discovering execution attack surfaces, correlating public
vulnerability advisories, tracking multi-step processing chains, and executing controlled non-destructive validation.`,
}

var rceDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover and prioritize RCE attack surfaces from endpoint intelligence",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rceFromDir == "" {
			return fmt.Errorf("--from directory is required")
		}

		ws, err := workspace.OpenRun(rceFromDir)
		if err != nil {
			return fmt.Errorf("open workspace '%s': %w", rceFromDir, err)
		}

		var epList []*endpoints.Endpoint
		if err := ws.LoadArtifact(workspace.EndpointsFile, &epList); err != nil {
			return fmt.Errorf("load endpoints.json: %w (run recon or crawl first)", err)
		}

		target := ws.Target
		if target == "" {
			target = "target"
		}

		// 1. Classify attack surfaces
		classifier := rce.NewClassifier()
		candidates := classifier.ClassifyEndpoints(target, epList)

		// 2. Correlate multi-step processing chains
		detector := rce.NewChainDetector()
		detector.CorrelateChains(candidates)

		// 3. Correlate public CVE intelligence
		registry := rce.NewAdvisoryRegistry()
		for _, cand := range candidates {
			matches := registry.CorrelateCandidate(cand)
			if len(matches) > 0 {
				cand.MatchingAdvisories = matches
			}
		}

		// 4. Calculate deterministic prioritisation scores
		prioritizer := rce.NewPrioritizer()
		prioritizer.PrioritizeCandidates(candidates)

		// Save candidates to workspace
		if err := ws.SaveArtifact(workspace.RCECandidatesFile, candidates); err != nil {
			return fmt.Errorf("save rce_candidates.json: %w", err)
		}

		fmt.Fprintf(os.Stderr, "[+] Discovered %d RCE attack surface candidates across %d endpoints\n",
			len(candidates), len(epList))
		fmt.Fprintf(os.Stderr, "[+] Saved to %s\n\n", filepath.Join(rceFromDir, workspace.RCECandidatesFile))

		// Print summary table to stdout
		fmt.Printf("%-10s %-20s %-8s %-35s %-12s\n", "PRIORITY", "CATEGORY", "METHOD", "ROUTE", "STATUS")
		fmt.Println(strings.Repeat("-", 90))
		for _, c := range candidates {
			fmt.Printf("%-10d %-20s %-8s %-35s %-12s\n",
				c.PriorityScore, c.Category, c.HTTPMethod, c.Route, c.ValidationStatus)
		}

		return nil
	},
}

var rceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List discovered RCE candidates from a workspace run",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rceFromDir == "" {
			return fmt.Errorf("--from directory is required")
		}

		ws, err := workspace.OpenRun(rceFromDir)
		if err != nil {
			return fmt.Errorf("open workspace '%s': %w", rceFromDir, err)
		}

		var candidates []*rce.RCECandidate
		if err := ws.LoadArtifact(workspace.RCECandidatesFile, &candidates); err != nil {
			return fmt.Errorf("load rce_candidates.json: %w (run 'scoutr rce discover' first)", err)
		}

		fmt.Printf("%-24s %-8s %-20s %-8s %-35s\n", "CANDIDATE ID", "SCORE", "CATEGORY", "METHOD", "ROUTE")
		fmt.Println(strings.Repeat("-", 100))
		for _, c := range candidates {
			fmt.Printf("%-24s %-8d %-20s %-8s %-35s\n",
				c.ID, c.PriorityScore, c.Category, c.HTTPMethod, c.Route)
		}

		return nil
	},
}

var rceValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate an RCE candidate using passive, safe active, or manual profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rceFromDir == "" {
			return fmt.Errorf("--from directory is required")
		}
		if rceCandidateID == "" {
			return fmt.Errorf("--candidate ID is required")
		}

		ws, err := workspace.OpenRun(rceFromDir)
		if err != nil {
			return fmt.Errorf("open workspace '%s': %w", rceFromDir, err)
		}

		var candidates []*rce.RCECandidate
		if err := ws.LoadArtifact(workspace.RCECandidatesFile, &candidates); err != nil {
			return fmt.Errorf("load rce_candidates.json: %w", err)
		}

		var targetCand *rce.RCECandidate
		for _, c := range candidates {
			if c.ID == rceCandidateID {
				targetCand = c
				break
			}
		}
		if targetCand == nil {
			return fmt.Errorf("candidate '%s' not found in workspace", rceCandidateID)
		}

		// Load scope
		sc, err := loadScopeOrWorkspace(globalConfig.ScopeFile, rceFromDir)
		if err != nil {
			return fmt.Errorf("resolve scope: %w", err)
		}

		// Initialize client
		client := httpx.New(httpx.Config{
			Scope:         sc,
			Timeout:       globalConfig.Timeout,
			GlobalRate:    globalConfig.Rate,
			PerHostRate:   globalConfig.RatePerHost,
			DryRun:        globalConfig.DryRun,
			UserAgent:     globalConfig.UserAgent,
			CustomHeaders: globalConfig.Headers,
		})

		validator := rce.NewValidator(client, sc)

		// Parse profile
		profile := rce.ProfileSafeActive
		switch strings.ToLower(rceProfileName) {
		case "passive":
			profile = rce.ProfilePassive
		case "manual":
			profile = rce.ProfileManual
		case "safe", "safe_active":
			profile = rce.ProfileSafeActive
		}

		// Optional auth profile
		var authProf *auth.Profile
		if rceAuthLabel != "" {
			profilesPath := filepath.Join(rceFromDir, "auth_profiles.json")
			if profiles, err := auth.LoadProfiles(profilesPath); err == nil {
				for _, p := range profiles {
					if strings.EqualFold(p.PrincipalLabel, rceAuthLabel) {
						authProf = p
						break
					}
				}
			}
		}

		attempt, err := validator.ValidateCandidate(context.Background(), targetCand, profile, authProf, rceCallbackURL)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		// Save updated candidates
		if err := ws.SaveArtifact(workspace.RCECandidatesFile, candidates); err != nil {
			return fmt.Errorf("save updated candidates: %w", err)
		}

		fmt.Fprintf(os.Stderr, "[+] Validation attempt completed: %s\n", attempt.AttemptID)
		fmt.Fprintf(os.Stderr, "[+] Status: %s | Execution Confirmed: %t\n", targetCand.ValidationStatus, attempt.ExecutionConfirmed)
		fmt.Fprintf(os.Stderr, "[+] Notes: %s\n", attempt.Notes)

		return nil
	},
}

var rceReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate an in-depth Markdown RCE research report",
	RunE: func(cmd *cobra.Command, args []string) error {
		if rceFromDir == "" {
			return fmt.Errorf("--from directory is required")
		}

		ws, err := workspace.OpenRun(rceFromDir)
		if err != nil {
			return fmt.Errorf("open workspace '%s': %w", rceFromDir, err)
		}

		var candidates []*rce.RCECandidate
		_ = ws.LoadArtifact(workspace.RCECandidatesFile, &candidates)

		registry := rce.NewAdvisoryRegistry()
		advisories := registry.GetAllAdvisories()

		reportMD := rce.GenerateReport(ws.Target, globalConfig.ScopeFile, candidates, advisories)

		if rceOutputFile != "" {
			if err := os.WriteFile(rceOutputFile, []byte(reportMD), 0644); err != nil {
				return fmt.Errorf("write report file: %w", err)
			}
			fmt.Fprintf(os.Stderr, "[+] RCE Report written to: %s\n", rceOutputFile)
		} else {
			fmt.Print(reportMD)
		}

		return nil
	},
}

func init() {
	rceDiscoverCmd.Flags().StringVar(&rceFromDir, "from", "", "Run directory containing endpoints.json (required)")

	rceListCmd.Flags().StringVar(&rceFromDir, "from", "", "Run directory containing rce_candidates.json (required)")

	rceValidateCmd.Flags().StringVar(&rceFromDir, "from", "", "Run directory containing rce_candidates.json (required)")
	rceValidateCmd.Flags().StringVar(&rceCandidateID, "candidate", "", "Candidate ID to validate (required)")
	rceValidateCmd.Flags().StringVar(&rceProfileName, "profile", "safe_active", "Validation profile: passive, safe_active, manual")
	rceValidateCmd.Flags().StringVar(&rceAuthLabel, "auth", "", "Principal label of authentication profile to use")
	rceValidateCmd.Flags().StringVar(&rceCallbackURL, "callback", "", "Optional researcher interaction callback URL")

	rceReportCmd.Flags().StringVar(&rceFromDir, "from", "", "Run directory containing rce_candidates.json (required)")
	rceReportCmd.Flags().StringVarP(&rceOutputFile, "output", "o", "", "Output file path (defaults to stdout)")

	rceCmd.AddCommand(rceDiscoverCmd)
	rceCmd.AddCommand(rceListCmd)
	rceCmd.AddCommand(rceValidateCmd)
	rceCmd.AddCommand(rceReportCmd)

	RootCmd.AddCommand(rceCmd)
}
