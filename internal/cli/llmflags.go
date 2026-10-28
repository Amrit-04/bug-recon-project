package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scoutr/scoutr/internal/triage"
)

// Shared Tier 2 LLM flags. Both `scoutr triage` and `scoutr report --draft`
// register these, so operator configuration is identical across the two
// agent-assisted stages.
var (
	llmProvider string
	llmEndpoint string
	llmModel    string
	llmTimeout  time.Duration
	llmNoLLM    bool
)

// addLLMFlags registers the Tier 2 flags on a command.
func addLLMFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&llmProvider, "llm-provider", "ollama",
		"LLM provider: ollama (local, default) or openai (any OpenAI-compatible endpoint)")
	cmd.Flags().StringVar(&llmEndpoint, "llm-endpoint", "",
		"LLM endpoint URL (default: http://127.0.0.1:11434). API keys are read from "+triage.APIKeyEnv+" only")
	cmd.Flags().StringVar(&llmModel, "llm-model", "",
		"Model name for the configured endpoint (required unless --no-llm)")
	cmd.Flags().DurationVar(&llmTimeout, "llm-timeout", 120*time.Second,
		"Per-batch LLM request timeout")
	cmd.Flags().BoolVar(&llmNoLLM, "no-llm", false,
		"Deterministic mode: skip the model entirely (every finding becomes needs_human)")
}

// buildLLMClient returns a client for the configured provider. A nil client
// (with nil error) means deterministic-only mode.
func buildLLMClient() (triage.Client, error) {
	if llmNoLLM {
		return nil, nil
	}
	model := strings.TrimSpace(llmModel)
	if model == "" {
		return nil, fmt.Errorf("--llm-model is required for LLM triage/drafting (or pass --no-llm for deterministic mode)")
	}
	return triage.NewClient(llmProvider, llmEndpoint, model, llmTimeout)
}

// llmModelName returns the model name recorded in artifacts.
func llmModelName() string {
	if llmNoLLM {
		return "deterministic"
	}
	return llmModel
}
