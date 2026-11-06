package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/server"
)

var (
	uiPort      int
	uiHost      string
	uiRunsDir   string
	uiNoBrowser bool
	uiFromRun   string
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Launch the local unified web dashboard (Tier 0-3)",
	Long: `Start a local HTTP server and web dashboard to explore scoutr audit workspaces.

Features:
  - Overview: KPI cards, severity distribution, 7-Check gate health
  - Attack Surface: Subdomains, open ports/services (naabu+nmap), live HTTP tech (httpx), crawled endpoints (katana), fuzzed paths (ffuf)
  - 7-Check Readiness Gate: Filter and inspect findings with redacted request/response evidence
  - Tier 2 Triage: AI classifications, confidence, rationale, and deterministic hard-rule overrides
  - Drafts & Approval: Markdown draft previews and the local submission_ready queue
  - Scope Guard: Interactive in-scope and out-of-scope policy inspection

The dashboard binds locally (127.0.0.1) and never transmits data to any external service.
`,
	Example: `  scoutr ui
  scoutr ui --port 8080 --no-browser
  scoutr ui --scope scope.yaml --from .scoutr/runs/example.com-20261028-101500`,
	RunE: runUI,
}

func init() {
	uiCmd.Flags().IntVarP(&uiPort, "port", "p", 8080, "Port to listen on")
	uiCmd.Flags().StringVar(&uiHost, "host", "127.0.0.1", "Host address to bind to")
	uiCmd.Flags().StringVar(&uiRunsDir, "runs-dir", ".scoutr/runs", "Base directory for workspace runs")
	uiCmd.Flags().StringVar(&uiFromRun, "from", "", "Specific run directory to inspect (optional)")
	uiCmd.Flags().BoolVar(&uiNoBrowser, "no-browser", false, "Do not automatically open the dashboard in the browser")
	RootCmd.AddCommand(uiCmd)
}

func runUI(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	addr := fmt.Sprintf("%s:%d", uiHost, uiPort)

	srv, err := server.New(server.Config{
		RunsDir:   uiRunsDir,
		ScopeFile: cfg.ScopeFile,
		Addr:      addr,
	})
	if err != nil {
		return fmt.Errorf("initialize dashboard server: %w", err)
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("start dashboard server: %w", err)
	}

	url := srv.URL()
	fmt.Fprintf(os.Stderr, "scoutr Unified Dashboard running at: %s\n", url)
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop the dashboard server.\n")

	if !uiNoBrowser {
		openBrowser(url)
	}

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigCh:
	case <-cmd.Context().Done():
	}

	fmt.Fprintf(os.Stderr, "\nShutting down dashboard server...\n")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return srv.Shutdown(ctx)
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = exec.Command("xdg-open", url).Start()
	}
	_ = err
}
