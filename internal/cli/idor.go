package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/auth"
	"github.com/scoutr/scoutr/internal/endpoints"
	"github.com/scoutr/scoutr/internal/findings"
	"github.com/scoutr/scoutr/internal/httpx"
	"github.com/scoutr/scoutr/internal/idor"
	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	idorFromDir       string
	idorProfilesFile  string
	idorUserA         string
	idorUserB         string
	idorHARFile       string
	idorOwnerLabel    string
	idorTenantLabel   string
	idorInstanceLabel string
)

var idorCmd = &cobra.Command{
	Use:   "idor",
	Short: "Insecure Direct Object Reference (IDOR) discovery and differential testing",
	Long: `Specialized IDOR research engine for identifying candidate object references
and conducting safe, read-only differential authorization testing between controlled accounts.`,
}

var idorInventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Build candidate object reference inventory from endpoint intelligence or HAR capture",
	RunE: func(cmd *cobra.Command, args []string) error {
		if idorFromDir == "" {
			return fmt.Errorf("--from directory is required")
		}

		objInv := idor.NewObjectInventory()

		// 1. Ingest existing endpoints if present
		endpointsPath := filepath.Join(idorFromDir, workspace.EndpointsFile)
		if _, err := os.Stat(endpointsPath); err == nil {
			data, err := os.ReadFile(endpointsPath)
			if err == nil {
				var epList []*endpoints.Endpoint
				if err := json.Unmarshal(data, &epList); err == nil {
					for _, ep := range epList {
						candidates := idor.ExtractCandidatesFromEndpoint(ep)
						objInv.AddAll(candidates)
					}
					fmt.Fprintf(os.Stderr, "Ingested endpoints from %s\n", endpointsPath)
				}
			}
		}

		// 2. Ingest HAR file if specified
		if idorHARFile != "" {
			harData, err := os.ReadFile(idorHARFile)
			if err != nil {
				return fmt.Errorf("read HAR file: %w", err)
			}
			var sc *scope.Scope
			if globalConfig.ScopeFile != "" {
				s, err := scope.LoadFromFile(globalConfig.ScopeFile)
				if err == nil {
					sc = s
				}
			}
			owner := idorOwnerLabel
			if owner == "" {
				owner = "owner"
			}
			tenant := idorTenantLabel
			if tenant == "" {
				tenant = "tenant_1"
			}
			imported, err := auth.ImportHAR(harData, sc, nil)
			if err != nil {
				return fmt.Errorf("import HAR: %w", err)
			}
			count := objInv.IngestHAR(imported, owner, tenant)
			fmt.Fprintf(os.Stderr, "Ingested %d candidates from HAR: %s\n", count, idorHARFile)
		}

		total := objInv.Count()
		fmt.Fprintf(os.Stderr, "Identified %d candidate object references\n", total)

		// Save to idor_objects.json and idor_candidates.json
		objectsPath := filepath.Join(idorFromDir, workspace.IDORObjectsFile)
		candidatesPath := filepath.Join(idorFromDir, workspace.IDORCandidatesFile)

		if err := objInv.SaveJSON(objectsPath); err != nil {
			return fmt.Errorf("save idor_objects: %w", err)
		}
		_ = objInv.SaveJSON(candidatesPath) // Mirror for convenience

		// Format output for stdout
		all := objInv.GetAll()
		outData, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return err
		}

		if globalConfig.OutputFile != "" {
			return os.WriteFile(globalConfig.OutputFile, outData, 0644)
		}
		fmt.Println(string(outData))
		return nil
	},
}

var idorCompareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Run safe, read-only differential authorization testing between User A (owner) and User B (tester)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if idorFromDir == "" {
			return fmt.Errorf("--from directory is required")
		}
		if idorUserA == "" || idorUserB == "" {
			return fmt.Errorf("--user-a and --user-b principal labels are required")
		}

		// Load scope
		sc, err := loadScopeOrWorkspace(globalConfig.ScopeFile, idorFromDir)
		if err != nil {
			return fmt.Errorf("scope required for active differential testing: %w", err)
		}

		// Load auth profiles
		profilesPath := idorProfilesFile
		if profilesPath == "" {
			profilesPath = filepath.Join(idorFromDir, "auth_profiles.json")
		}
		profiles, err := auth.LoadProfiles(profilesPath)
		if err != nil {
			return fmt.Errorf("load profiles from %s: %w", profilesPath, err)
		}

		var profileA *auth.Profile
		var profileB *auth.Profile
		for _, p := range profiles {
			if strings.EqualFold(p.PrincipalLabel, idorUserA) {
				profileA = p
			}
			if strings.EqualFold(p.PrincipalLabel, idorUserB) {
				profileB = p
			}
		}

		if profileA == nil {
			return fmt.Errorf("profile for user-a '%s' not found in %s", idorUserA, profilesPath)
		}
		if profileB == nil {
			return fmt.Errorf("profile for user-b '%s' not found in %s", idorUserB, profilesPath)
		}

		// Load candidates
		objInv := idor.NewObjectInventory()
		objectsPath := filepath.Join(idorFromDir, workspace.IDORObjectsFile)
		if err := objInv.LoadJSON(objectsPath); err != nil {
			// Try fallback to idor_candidates.json
			candidatesPath := filepath.Join(idorFromDir, workspace.IDORCandidatesFile)
			if err2 := objInv.LoadJSON(candidatesPath); err2 != nil {
				return fmt.Errorf("load candidates from %s: %w", objectsPath, err)
			}
		}

		candidates := objInv.GetAll()
		if len(candidates) == 0 {
			fmt.Fprintln(os.Stderr, "No candidate object references found to test.")
			return nil
		}

		fmt.Fprintf(os.Stderr, "Starting differential testing on %d candidates between '%s' (owner) and '%s' (tester)\n",
			len(candidates), profileA.PrincipalLabel, profileB.PrincipalLabel)

		client := httpx.New(httpx.Config{
			Scope:         sc,
			Timeout:       globalConfig.Timeout,
			MaxBodySize:   globalConfig.MaxBodyBytes,
			GlobalRate:    globalConfig.Rate,
			PerHostRate:   globalConfig.RatePerHost,
			DryRun:        globalConfig.DryRun,
			UserAgent:     globalConfig.UserAgent,
			CustomHeaders: globalConfig.Headers,
		})

		engine := idor.NewCompareEngine(client)
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		var comparisons []*idor.ComparisonResult
		var confirmedFindings []*findings.Finding

		for i, cand := range candidates {
			fmt.Fprintf(os.Stderr, "[%d/%d] Testing %s (%s)...\n", i+1, len(candidates), cand.RouteTemplate, cand.ObjectID)
			comp, err := engine.CompareCandidate(ctx, cand, profileA, profileB)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
				continue
			}

			status, finding, _ := idor.ValidateComparison(comp)
			comp.Status = status
			comparisons = append(comparisons, comp)

			if finding != nil {
				confirmedFindings = append(confirmedFindings, finding)
				fmt.Fprintf(os.Stderr, "  [!] %s: %s\n", status, finding.Title)
			} else {
				fmt.Fprintf(os.Stderr, "  Status: %s (%s)\n", status, comp.EvidenceNotes)
			}
		}

		// Save comparisons to idor_comparisons.json
		compPath := filepath.Join(idorFromDir, workspace.IDORComparisonsFile)
		compData, err := json.MarshalIndent(comparisons, "", "  ")
		if err == nil {
			_ = os.WriteFile(compPath, compData, 0644)
			fmt.Fprintf(os.Stderr, "Saved %d comparisons to %s\n", len(comparisons), compPath)
		}

		// Append any validated findings to workspace raw_findings.json
		if len(confirmedFindings) > 0 {
			ws, err := workspace.OpenRun(idorFromDir)
			if err == nil {
				added, _ := appendRawFindings(ws, confirmedFindings)
				fmt.Fprintf(os.Stderr, "Recorded %d IDOR findings to workspace\n", added)
			}
		}

		if globalConfig.OutputFile != "" {
			_ = os.WriteFile(globalConfig.OutputFile, compData, 0644)
		}
		return nil
	},
}

var idorReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate human-readable IDOR research markdown report from comparison results",
	RunE: func(cmd *cobra.Command, args []string) error {
		if idorFromDir == "" {
			return fmt.Errorf("--from directory is required")
		}

		compPath := filepath.Join(idorFromDir, workspace.IDORComparisonsFile)
		data, err := os.ReadFile(compPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", compPath, err)
		}

		var comparisons []*idor.ComparisonResult
		if err := json.Unmarshal(data, &comparisons); err != nil {
			return fmt.Errorf("unmarshal comparisons: %w", err)
		}

		var findingList []*findings.Finding
		for _, comp := range comparisons {
			_, finding, _ := idor.ValidateComparison(comp)
			if finding != nil {
				findingList = append(findingList, finding)
			}
		}

		reportMD := idor.GenerateIDORReportMarkdown(comparisons, findingList)

		if globalConfig.OutputFile != "" {
			if err := os.WriteFile(globalConfig.OutputFile, []byte(reportMD), 0644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Wrote IDOR report to %s\n", globalConfig.OutputFile)
		} else {
			fmt.Println(reportMD)
		}

		return nil
	},
}

func loadScopeOrWorkspace(scopeFile, runDir string) (*scope.Scope, error) {
	if scopeFile != "" {
		return scope.LoadFromFile(scopeFile)
	}
	// Try loading scope from workspace target
	ws, err := workspace.OpenRun(runDir)
	if err == nil && ws.Target != "" {
		return scope.New([]string{ws.Target, "*." + ws.Target}, nil), nil
	}
	return nil, fmt.Errorf("no scope file provided and run directory target is unset")
}

func init() {
	// idor inventory flags
	idorInventoryCmd.Flags().StringVar(&idorFromDir, "from", "", "Run directory containing endpoints.json or workspace (required)")
	idorInventoryCmd.Flags().StringVar(&idorHARFile, "har", "", "Optional path to researcher-provided HAR capture")
	idorInventoryCmd.Flags().StringVar(&idorOwnerLabel, "owner", "owner", "Principal label for objects discovered in HAR")
	idorInventoryCmd.Flags().StringVar(&idorTenantLabel, "tenant", "tenant_1", "Tenant label for objects discovered in HAR")

	// idor compare flags
	idorCompareCmd.Flags().StringVar(&idorFromDir, "from", "", "Run directory containing idor_objects.json (required)")
	idorCompareCmd.Flags().StringVar(&idorProfilesFile, "profiles", "", "Path to auth profiles JSON file (defaults to <from>/auth_profiles.json)")
	idorCompareCmd.Flags().StringVar(&idorUserA, "user-a", "", "Principal label of owner account (e.g. 'owner', 'alice') (required)")
	idorCompareCmd.Flags().StringVar(&idorUserB, "user-b", "", "Principal label of tester account (e.g. 'tester', 'bob') (required)")

	// idor report flags
	idorReportCmd.Flags().StringVar(&idorFromDir, "from", "", "Run directory containing idor_comparisons.json (required)")

	idorCmd.AddCommand(idorInventoryCmd)
	idorCmd.AddCommand(idorCompareCmd)
	idorCmd.AddCommand(idorReportCmd)

	RootCmd.AddCommand(idorCmd)
}
