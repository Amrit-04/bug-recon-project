package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/config"
)

// Global config that gets populated by the root command
var globalConfig = config.Defaults()

// RootCmd is the root cobra command for scoutr
var RootCmd = &cobra.Command{
	Use:   "scoutr",
	Short: "scoutr - a fast, lightweight, scope-safe recon and misconfiguration scanner",
	Long: `scoutr - a fast, lightweight, scope-safe recon and misconfiguration scanner

A CLI tool for bug bounty hunters to do recon and run safe, well-understood,
non-exploitative checks against targets they are authorized to test.

Usage:
  scoutr enum   --scope scope.yaml [--passive-only] [--wordlist subs.txt] -o subs.jsonl
  scoutr probe  --scope scope.yaml -i subs.jsonl -o live.jsonl
  scoutr scan   --scope scope.yaml -i live.jsonl [--checks ...] [--skip ...] -o findings.jsonl
  scoutr report -i findings.jsonl --format md|html|json -o report.md
  scoutr run    --scope scope.yaml     # full pipeline: enum -> probe -> scan -> report

For more information, visit https://github.com/scoutr/scoutr
`,
	SilenceUsage: true,
}

func init() {
	// Scope (required for most commands)
	RootCmd.PersistentFlags().StringVar(&globalConfig.ScopeFile, "scope", "",
		"Path to scope YAML file (required)")

	// Output
	RootCmd.PersistentFlags().StringVarP(&globalConfig.OutputFile, "output", "o", "",
		"Output file (default: stdout)")
	RootCmd.PersistentFlags().StringVarP(&globalConfig.Format, "format", "f", "jsonl",
		"Output format: jsonl, md, html")
	RootCmd.PersistentFlags().BoolVar(&globalConfig.NoColor, "no-color", false,
		"Disable colored output")
	RootCmd.PersistentFlags().BoolVarP(&globalConfig.Verbose, "verbose", "v", false,
		"Enable verbose logging")
	RootCmd.PersistentFlags().BoolVar(&globalConfig.DryRun, "dry-run", false,
		"Show what would be requested without sending anything")

	// Concurrency & Performance
	RootCmd.PersistentFlags().IntVar(&globalConfig.Concurrency, "concurrency", 25,
		"Number of concurrent workers")
	RootCmd.PersistentFlags().Float64Var(&globalConfig.Rate, "rate", 10.0,
		"Global rate limit (requests/second)")
	RootCmd.PersistentFlags().Float64Var(&globalConfig.RatePerHost, "rate-per-host", 3.0,
		"Rate limit per host (requests/second)")
	RootCmd.PersistentFlags().DurationVar(&globalConfig.Timeout, "timeout", 30*time.Second,
		"Request timeout")
	RootCmd.PersistentFlags().Int64Var(&globalConfig.MaxBodyBytes, "max-body", 1024*1024,
		"Maximum response body size to read (bytes)")

	// User-Agent and headers
	RootCmd.PersistentFlags().StringVar(&globalConfig.UserAgent, "user-agent", "",
		"Custom User-Agent string (default: scoutr/1.0)")
	RootCmd.PersistentFlags().StringToStringVar(&globalConfig.Headers, "header", nil,
		"Custom HTTP headers (e.g., --header X-Bug-Bounty:myhandle)")

	// Recon flags
	RootCmd.PersistentFlags().BoolVar(&globalConfig.PassiveOnly, "passive-only", false,
		"Use only passive recon (no DNS brute force)")
	RootCmd.PersistentFlags().BoolVar(&globalConfig.Brute, "brute", false,
		"Enable DNS brute force (requires wordlist)")
	RootCmd.PersistentFlags().StringVar(&globalConfig.Wordlist, "wordlist", "",
		"Path to custom wordlist (overrides embedded default)")

	// Checks flags
	RootCmd.PersistentFlags().StringSliceVar(&globalConfig.Checks, "checks", nil,
		"Comma-separated list of checks to run (e.g., headers,cookies,exposure)")
	RootCmd.PersistentFlags().StringSliceVar(&globalConfig.SkipChecks, "skip", nil,
		"Comma-separated list of checks to skip (e.g., cors,tls)")

	// Add subcommands
	RootCmd.AddCommand(enumCmd)
	RootCmd.AddCommand(probeCmd)
	RootCmd.AddCommand(scanCmd)
	RootCmd.AddCommand(reportCmd)
	RootCmd.AddCommand(runCmd)
}

// Execute runs the root command with signal handling for graceful shutdown.
func Execute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Validate config
	if err := globalConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Print banner
	printBanner(globalConfig)

	return RootCmd.ExecuteContext(ctx)
}

// printBanner displays the tool banner and configuration summary.
func printBanner(cfg *config.Config) {
	if cfg.NoColor {
		fmt.Printf("scoutr v1.0 - scope-safe recon and misconfiguration scanner\n")
		if cfg.ScopeFile != "" {
			fmt.Printf("Scope: %s\n", cfg.ScopeFile)
		}
		fmt.Printf("Concurrency: %d | Rate: %.1f/s | Per-Host: %.1f/s\n",
			cfg.Concurrency, cfg.Rate, cfg.RatePerHost)
		fmt.Printf("Timeout: %s | Max Body: %d bytes\n", cfg.Timeout, cfg.MaxBodyBytes)
		if cfg.DryRun {
			fmt.Printf("DRY RUN MODE - No requests will be sent\n")
		}
		return
	}

	fmt.Printf("\x1b[1;36m%s\x1b[0m - \x1b[1;32mscope-safe recon and misconfiguration scanner\x1b[0m\n", "scoutr v1.0")
	if cfg.ScopeFile != "" {
		fmt.Printf("Scope: \x1b[33m%s\x1b[0m\n", cfg.ScopeFile)
	}
	fmt.Printf("Concurrency: \x1b[36m%d\x1b[0m | Rate: \x1b[36m%.1f/s\x1b[0m | Per-Host: \x1b[36m%.1f/s\x1b[0m\n",
		cfg.Concurrency, cfg.Rate, cfg.RatePerHost)
	fmt.Printf("Timeout: \x1b[36m%s\x1b[0m | Max Body: \x1b[36m%d bytes\x1b[0m\n", cfg.Timeout, cfg.MaxBodyBytes)
	if cfg.DryRun {
		fmt.Printf("\x1b[1;33mDRY RUN MODE - No requests will be sent\x1b[0m\n")
	}
	fmt.Printf("\n")
}
