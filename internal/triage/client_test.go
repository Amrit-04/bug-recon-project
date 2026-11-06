package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClientProviders(t *testing.T) {
	tests := []struct {
		provider     string
		endpoint     string
		model        string
		wantName     string
		wantEndpoint string
	}{
		{"ollama", "", "llama3.2", "ollama", DefaultOllamaEndpoint},
		{"", "", "llama3.2", "ollama", DefaultOllamaEndpoint},
		{"openai", "", "gpt-4o", "openai", DefaultOpenAIEndpoint},
		{"lmstudio", "", "mistral-7b", "lmstudio", DefaultLMStudioEndpoint},
		{"lm-studio", "", "mistral-7b", "lmstudio", DefaultLMStudioEndpoint},
		{"llamacpp", "", "qwen2.5", "llamacpp", DefaultLlamaCppEndpoint},
		{"llama.cpp", "", "qwen2.5", "llamacpp", DefaultLlamaCppEndpoint},
		{"lmstudio", "http://192.168.1.100:1234/v1", "custom", "lmstudio", "http://192.168.1.100:1234/v1"},
		{"llamacpp", "http://192.168.1.100:8080/v1", "custom", "llamacpp", "http://192.168.1.100:8080/v1"},
	}

	for _, tt := range tests {
		client, err := NewClient(tt.provider, tt.endpoint, tt.model, 5*time.Second)
		if err != nil {
			t.Fatalf("NewClient(%q, %q, %q): unexpected error: %v", tt.provider, tt.endpoint, tt.model, err)
		}
		if client.Name() != tt.wantName {
			t.Errorf("NewClient(%q) Name() = %q, want %q", tt.provider, client.Name(), tt.wantName)
		}
	}
}

func TestNewClientValidation(t *testing.T) {
	// Missing model
	if _, err := NewClient("lmstudio", "", "", 0); err == nil {
		t.Error("expected error for empty model, got nil")
	}

	// Unsupported provider
	if _, err := NewClient("unknown_cloud", "", "model", 0); err == nil {
		t.Error("expected error for unsupported provider, got nil")
	}

	// Invalid endpoint scheme
	if _, err := NewClient("lmstudio", "ftp://localhost:1234", "model", 0); err == nil {
		t.Error("expected error for non-http endpoint, got nil")
	}
}

func TestLMStudioCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := map[string]any{
			"model": "local-model",
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"content": `{"findings":[{"finding_id":"F1","classification":"likely_true","rationale":"test","confidence":90}]}`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("lmstudio", server.URL, "local-model", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, err := client.Complete(context.Background(), CompletionRequest{
		System: "prompt",
		User:   "evidence",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if res.Model != "local-model" {
		t.Errorf("got model %q, want local-model", res.Model)
	}
	if res.Content == "" {
		t.Error("expected non-empty content")
	}
}

func TestLlamaCppCompletion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := map[string]any{
			"model": "qwen2.5-coder",
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"content": `{"findings":[{"finding_id":"F2","classification":"needs_human","rationale":"ambiguous","confidence":50}]}`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient("llamacpp", server.URL, "qwen2.5-coder", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, err := client.Complete(context.Background(), CompletionRequest{
		System: "prompt",
		User:   "evidence",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if res.Model != "qwen2.5-coder" {
		t.Errorf("got model %q, want qwen2.5-coder", res.Model)
	}
}
