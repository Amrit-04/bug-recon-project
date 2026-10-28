package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// CompletionRequest is the structured prompt sent to a model. Free-text chat is
// never used: the system prompt pins the JSON contract.
type CompletionRequest struct {
	System string
	User   string
}

// CompletionResponse is the raw model output. Callers must parse it as JSON and
// must never treat unparseable output as a verdict.
type CompletionResponse struct {
	Content string
	Model   string
}

// Client is the pluggable LLM interface.
//
// Implementations MUST NOT receive the scope file, raw target lists or any
// secret material. Triage only ever passes redacted finding evidence.
type Client interface {
	// Name returns a short provider identifier persisted in triage.json.
	Name() string
	// Complete performs a single non-streaming JSON-mode completion.
	Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
}

// DefaultEndpoints for the supported providers.
const (
	DefaultOllamaEndpoint = "http://127.0.0.1:11434"
	DefaultOpenAIEndpoint = "http://127.0.0.1:11434/v1"
	// APIKeyEnv is the only place an API key is read from: keys never appear
	// in flags, workspace artifacts or triage.json.
	APIKeyEnv = "SCOUTR_LLM_API_KEY"
)

// newHTTPClient builds the HTTP client used for LLM calls. Redirects are not
// followed: the endpoint is operator-configured, and a redirected completion
// request would silently change where finding evidence is sent.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("LLM endpoint redirect to %s refused", req.URL.Redacted())
		},
	}
}

// NewClient builds a client for the given provider.
//
// Supported providers:
//   - "ollama": native Ollama /api/chat with format=json
//   - "openai": any OpenAI-compatible /v1/chat/completions endpoint
func NewClient(provider, endpoint, model string, timeout time.Duration) (Client, error) {
	if strings.TrimSpace(model) == "" {
		return nil, fmt.Errorf("LLM model name is required")
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "ollama":
		if endpoint == "" {
			endpoint = DefaultOllamaEndpoint
		}
		if err := validateEndpoint(endpoint); err != nil {
			return nil, err
		}
		return &OllamaClient{
			endpoint: strings.TrimRight(endpoint, "/"),
			model:    model,
			http:     newHTTPClient(timeout),
		}, nil
	case "openai":
		if endpoint == "" {
			endpoint = DefaultOpenAIEndpoint
		}
		if err := validateEndpoint(endpoint); err != nil {
			return nil, err
		}
		return &OpenAIClient{
			endpoint: strings.TrimRight(endpoint, "/"),
			model:    model,
			apiKey:   os.Getenv(APIKeyEnv),
			http:     newHTTPClient(timeout),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported LLM provider %q (supported: ollama, openai)", provider)
	}
}

// validateEndpoint rejects empty or non-HTTP endpoints early so a typo cannot
// turn into a local file read.
func validateEndpoint(endpoint string) error {
	switch {
	case endpoint == "":
		return fmt.Errorf("LLM endpoint is required")
	case strings.HasPrefix(endpoint, "http://"), strings.HasPrefix(endpoint, "https://"):
		return nil
	default:
		return fmt.Errorf("LLM endpoint must be an http(s) URL, got %q", endpoint)
	}
}

// OllamaClient talks to a local Ollama server (the default for sub-9B models).
type OllamaClient struct {
	endpoint string
	model    string
	http     *http.Client
}

// Name implements Client.
func (c *OllamaClient) Name() string { return "ollama" }

// Complete implements Client using Ollama's JSON mode.
func (c *OllamaClient) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	body := map[string]any{
		"model":  c.model,
		"stream": false,
		"format": "json",
		"messages": []map[string]string{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.User},
		},
		"options": map[string]any{
			"temperature": 0,
			"num_predict": 1500,
		},
	}

	raw, err := postJSON(ctx, c.http, c.endpoint+"/api/chat", body, nil)
	if err != nil {
		return CompletionResponse{}, err
	}

	var resp struct {
		Model   string `json:"model"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return CompletionResponse{}, fmt.Errorf("decode ollama response: %w", err)
	}
	if resp.Error != "" {
		return CompletionResponse{}, fmt.Errorf("ollama error: %s", resp.Error)
	}
	if strings.TrimSpace(resp.Message.Content) == "" {
		return CompletionResponse{}, fmt.Errorf("ollama returned an empty completion")
	}
	if resp.Model == "" {
		resp.Model = c.model
	}
	return CompletionResponse{Content: resp.Message.Content, Model: resp.Model}, nil
}

// OpenAIClient talks to any OpenAI-compatible chat completions endpoint.
type OpenAIClient struct {
	endpoint string
	model    string
	apiKey   string
	http     *http.Client
}

// Name implements Client.
func (c *OpenAIClient) Name() string { return "openai" }

// Complete implements Client using response_format=json_object.
func (c *OpenAIClient) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	body := map[string]any{
		"model":       c.model,
		"temperature": 0,
		"stream":      false,
		"messages": []map[string]string{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.User},
		},
		"response_format": map[string]string{"type": "json_object"},
	}

	headers := map[string]string{}
	if c.apiKey != "" {
		headers["Authorization"] = "Bearer " + c.apiKey
	}

	raw, err := postJSON(ctx, c.http, c.completionsURL(), body, headers)
	if err != nil {
		return CompletionResponse{}, err
	}

	var resp struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return CompletionResponse{}, fmt.Errorf("decode openai-compatible response: %w", err)
	}
	if len(resp.Choices) == 0 || strings.TrimSpace(resp.Choices[0].Message.Content) == "" {
		return CompletionResponse{}, fmt.Errorf("openai-compatible endpoint returned no completion")
	}
	if resp.Model == "" {
		resp.Model = c.model
	}
	return CompletionResponse{Content: resp.Choices[0].Message.Content, Model: resp.Model}, nil
}

func (c *OpenAIClient) completionsURL() string {
	if strings.HasSuffix(c.endpoint, "/v1") {
		return c.endpoint + "/chat/completions"
	}
	return c.endpoint + "/v1/chat/completions"
}

// postJSON performs a POST with a JSON body and returns the raw response body.
func postJSON(ctx context.Context, client *http.Client, url string, body any, headers map[string]string) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal LLM request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build LLM request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("call LLM endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Bound the response: a local model cannot exhaust memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read LLM response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("LLM endpoint returned HTTP %d: %s", resp.StatusCode, truncate(string(raw), 400))
	}
	return raw, nil
}

// MockClient is a deterministic Client for tests and for --no-llm dry runs.
type MockClient struct {
	Provider string
	Func     func(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
}

// Name implements Client.
func (m *MockClient) Name() string {
	if m.Provider == "" {
		return "mock"
	}
	return m.Provider
}

// Complete implements Client.
func (m *MockClient) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	if m.Func == nil {
		return CompletionResponse{}, fmt.Errorf("mock client has no handler")
	}
	return m.Func(ctx, req)
}
