package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/scope"
	"github.com/scoutr/scoutr/internal/tools"
	"github.com/scoutr/scoutr/internal/workspace"
)

var (
	portsInputFile   string
	portsFromRun     string
	portsTopPorts    int
	portsSkipService bool
	portsProbe       bool
)

var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Discover open ports (naabu) and fingerprint services (nmap -sV)",
	Long: `Tier 1 active port discovery with deliberately conservative defaults.

Pipeline placement: after dnsx resolution and before httpx probing.

  - naabu runs a TCP connect scan against the top 100 ports (opt into the
    top 1000 profile with --top-ports 1000). Full 65,535-port sweeps are not
    supported by design.
  - nmap runs -sV with --version-light on exactly the ports naabu discovered
    and never performs its own port sweep. Disable with --skip-service-detection.
  - every stage is rate limited and every host is scope-checked before the
    binary is executed.

Results are written to <run-dir>/ports.json when --from <run-dir> is supplied,
so subsequent stages (httpx, triage) can read them back.
`,
	Example: `  scoutr ports --scope scope.yaml -i hosts.jsonl -o ports.jsonl
  scoutr ports --scope scope.yaml --from .scoutr/runs/example.com-20261028-101500
  scoutr ports --scope scope.yaml --top-ports 1000 --probe`,
	RunE: runPorts,
}

func init() {
	portsCmd.Flags().StringVarP(&portsInputFile, "input", "i", "", "Input file of hosts/URLs (JSONL)")
	portsCmd.Flags().StringVar(&portsFromRun, "from", "", "Workspace run directory to read inventory from and write artifacts to")
	portsCmd.Flags().IntVar(&portsTopPorts, "top-ports", tools.DefaultNaabuTopPorts, "Port budget: 100 (default) or 1000")
	portsCmd.Flags().BoolVar(&portsSkipService, "skip-service-detection", false, "Skip nmap -sV service/version detection")
	portsCmd.Flags().BoolVar(&portsProbe, "probe", false, "Feed discovered ports into httpx and print live HTTP endpoints")
	RootCmd.AddCommand(portsCmd)
}

func runPorts(cmd *cobra.Command, args []string) error {
	cfg := globalConfig
	ctx := cmd.Context()

	if cfg.ScopeFile == "" {
		return fmt.Errorf("--scope is required")
	}
	s, err := scope.LoadFromFile(cfg.ScopeFile)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}

	var ws *workspace.Workspace
	var hosts []string
	if portsFromRun != "" {
		ws, err = workspace.OpenRun(portsFromRun)
		if err != nil {
			return fmt.Errorf("open workspace: %w", err)
		}
		hosts, err = ws.LoadInventory()
		if err != nil {
			return fmt.Errorf("load inventory: %w", err)
		}
	} else {
		hosts, err = readTargetsFromInput(portsInputFile)
		if err != nil {
			return err
		}
	}

	hosts = tools.FilterTargetsInScope(s, hosts)
	if len(hosts) == 0 {
		return fmt.Errorf("no in-scope hosts to scan")
	}

	topPorts := tools.NormalizeTopPorts(portsTopPorts)

	if cfg.DryRun {
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Scope file: %s\n", cfg.ScopeFile)
		fmt.Fprintf(os.Stderr, "[DRY-RUN] Would run naabu -top-ports %d -scan-type c -rl %d on %d hosts\n", topPorts, int(cfg.Rate), len(hosts))
		if !portsSkipService {
			fmt.Fprintf(os.Stderr, "[DRY-RUN] Would run nmap -sV --version-light on exactly the discovered ports only\n")
		}
		if portsProbe {
			fmt.Fprintf(os.Stderr, "[DRY-RUN] Would feed discovered ports into httpx\n")
		}
		return nil
	}

	runner := tools.NewExecRunner()
	logger := loggerFor(cfg.Verbose)

	ports, err := tools.RunNaabu(ctx, runner, s, hosts, topPorts, int(cfg.Rate), logger)
	if err != nil {
		return fmt.Errorf("port discovery: %w", err)
	}
	fmt.Printf("naabu discovered %d open ports on %d in-scope hosts\n", len(ports), len(hosts))

	if !portsSkipService && len(ports) > 0 {
		services, err := tools.RunNmapServiceScan(ctx, runner, s, tools.NmapTargets(ports), int(cfg.Rate), logger)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Warning: nmap service detection failed: %v\n", err)
		}
		ports = mergeServiceFingerprints(ports, services)
	}

	if ws != nil {
		if err := ws.SaveArtifact(workspace.PortsFile, ports); err != nil {
			return fmt.Errorf("save port artifact: %w", err)
		}
		fmt.Printf("Saved port inventory to: %s/%s\n", ws.Dir, workspace.PortsFile)
	}

	if portsProbe {
		live, err := runHTTPXStage(ctx, s, tools.BuildHTTPXTargets(hosts, ports), int(cfg.Rate), logger)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "Warning: httpx probe failed: %v\n", err)
		}
		if ws != nil {
			if err := ws.SaveArtifact(workspace.HTTPXFile, live); err != nil {
				return fmt.Errorf("save httpx artifact: %w", err)
			}
		}
		fmt.Printf("httpx found %d live HTTP endpoints from discovered ports\n", len(live))
	}

	if cfg.OutputFile != "" {
		values := make([]any, 0, len(ports))
		for _, p := range ports {
			values = append(values, p)
		}
		if err := writeJSONL(cfg.OutputFile, values); err != nil {
			return err
		}
		fmt.Printf("Wrote %d port records to %s\n", len(ports), cfg.OutputFile)
	}

	return nil
}

// mergeServiceFingerprints folds nmap -sV results into the naabu port list,
// keeping the port set exactly as naabu discovered it.
func mergeServiceFingerprints(ports, services []tools.PortResult) []tools.PortResult {
	type key struct {
		host string
		port int
	}
	index := make(map[key]int, len(ports))
	for i, p := range ports {
		index[key{p.Host, p.Port}] = i
	}

	for _, svc := range services {
		k := key{svc.Host, svc.Port}
		i, ok := index[k]
		if !ok {
			// nmap only ever targets naabu's port list, so an unknown row means
			// a parsing/host-normalisation mismatch. Appending it would widen
			// the result beyond the ports naabu actually found.
			continue
		}
		ports[i].Service = svc.Service
		ports[i].Product = svc.Product
		ports[i].Version = svc.Version
		if ports[i].IP == "" {
			ports[i].IP = svc.IP
		}
		ports[i].Source = "naabu+nmap"
	}

	sort.SliceStable(ports, func(i, j int) bool {
		if ports[i].Host == ports[j].Host {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Host < ports[j].Host
	})
	return ports
}
