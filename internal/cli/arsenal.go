package cli

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/tools"
)

var arsenalCmd = &cobra.Command{
	Use:   "arsenal",
	Short: "Inspect PATH for supported external recon tools",
	Long: `Inspect PATH for supported external discovery & posture tools.

Displays installed status, detected version, trust tier (Passive OSINT vs Read-Only Probe),
and one-line manual install hints.

scoutr NEVER auto-installs external binaries at runtime. All tools must be installed
manually by the operator.
`,
	RunE: runArsenal,
}

func init() {
	RootCmd.AddCommand(arsenalCmd)
}

func runArsenal(cmd *cobra.Command, args []string) error {
	runner := tools.NewExecRunner()
	ctx := cmd.Context()

	statuses := tools.InspectArsenal(ctx, runner)

	var out io.Writer = os.Stdout
	if globalConfig.OutputFile != "" {
		f, err := os.Create(globalConfig.OutputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	fmt.Fprintf(out, "scoutr Arsenal — External Tool Status & Trust Tiers\n\n")

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "TOOL\tSTATUS\tVERSION\tTRUST TIER\tMANUAL INSTALL HINT\n")
	fmt.Fprintf(w, "----\t------\t-------\t----------\t-------------------\n")

	for _, s := range statuses {
		statusStr := "[MISSING]"
		if s.Installed {
			statusStr = "[OK]"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			s.Name,
			statusStr,
			s.Version,
			s.Tier,
			s.InstallHint,
		)
	}
	w.Flush()

	fmt.Fprintf(out, "\nTrust Tier Summary:\n")
	fmt.Fprintf(out, "  * Passive OSINT: Queries third-party datasets/archives only. Zero packets to target.\n")
	fmt.Fprintf(out, "  * Read-Only Probe: Direct non-intrusive observation requests strictly to in-scope targets.\n")

	return nil
}
