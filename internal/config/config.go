package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all runtime configuration with precedence: flags > config file > defaults.
type Config struct {
	// Scope
	ScopeFile string

	// Rate limiting & timeouts
	Rate         float64 // requests per second (global)
	RatePerHost  float64 // requests per second per host
	Timeout      time.Duration
	MaxBodyBytes int64

	// Output
	OutputFile string
	Format     string // "jsonl", "md", "html"
	NoColor    bool
	Verbose    bool

	// Safety
	DryRun    bool
	UserAgent string
	Headers   map[string]string

	// Recon
	PassiveOnly bool
	Brute       bool
	Wordlist    string
	External    bool

	// Posture verification
	VerifyPosture bool
}

// FileConfig is the structure of .scoutr.yaml config files.
type FileConfig struct {
	Rate          *float64          `yaml:"rate,omitempty"`
	RatePerHost   *float64          `yaml:"rate_per_host,omitempty"`
	Timeout       *string           `yaml:"timeout,omitempty"` // e.g., "30s"
	MaxBodyBytes  *int64            `yaml:"max_body_bytes,omitempty"`
	UserAgent     *string           `yaml:"user_agent,omitempty"`
	Headers       map[string]string `yaml:"headers,omitempty"`
	External      *bool             `yaml:"external,omitempty"`
	VerifyPosture *bool             `yaml:"verify_posture,omitempty"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Rate:         10.0,
		RatePerHost:  3.0,
		Timeout:      30 * time.Second,
		MaxBodyBytes: 1024 * 1024, // 1 MB
		Format:       "jsonl",
		UserAgent:    "scoutr/1.0 (https://github.com/scoutr/scoutr)",
		Headers:      make(map[string]string),
	}
}

// LoadFromFile reads a .scoutr.yaml config file and merges it with defaults.
func LoadFromFile(path string) (*Config, error) {
	fc, err := LoadFileConfig(path)
	if err != nil {
		return nil, err
	}

	cfg := Defaults()
	fc.Apply(cfg, nil)
	return cfg, nil
}

// LoadFileConfig reads and parses a .scoutr.yaml config file without applying
// it, so the caller can decide precedence per key.
func LoadFileConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}
	return &fc, nil
}

// Apply merges the file config into cfg. A key is skipped when override reports
// that the corresponding flag was set on the command line, which is what makes
// the documented precedence (flags > config file > defaults) hold.
func (fc *FileConfig) Apply(cfg *Config, override func(flagName string) bool) {
	set := func(flagName string, apply func()) {
		if override != nil && override(flagName) {
			return
		}
		apply()
	}

	set("rate", func() {
		if fc.Rate != nil {
			cfg.Rate = *fc.Rate
		}
	})
	set("rate-per-host", func() {
		if fc.RatePerHost != nil {
			cfg.RatePerHost = *fc.RatePerHost
		}
	})
	set("timeout", func() {
		if fc.Timeout != nil {
			if d, err := time.ParseDuration(*fc.Timeout); err == nil {
				cfg.Timeout = d
			}
		}
	})
	set("max-body", func() {
		if fc.MaxBodyBytes != nil {
			cfg.MaxBodyBytes = *fc.MaxBodyBytes
		}
	})
	set("user-agent", func() {
		if fc.UserAgent != nil {
			cfg.UserAgent = *fc.UserAgent
		}
	})
	set("header", func() {
		if fc.Headers != nil {
			cfg.Headers = fc.Headers
		}
	})
	set("external", func() {
		if fc.External != nil {
			cfg.External = *fc.External
		}
	})
	set("verify-posture", func() {
		if fc.VerifyPosture != nil {
			cfg.VerifyPosture = *fc.VerifyPosture
		}
	})
}

// Validate checks that the config is valid.
func (c *Config) Validate() error {
	if c.Rate < 0 {
		return fmt.Errorf("rate must be non-negative")
	}
	if c.RatePerHost < 0 {
		return fmt.Errorf("rate_per_host must be non-negative")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if c.MaxBodyBytes < 1 {
		return fmt.Errorf("max_body_bytes must be at least 1")
	}
	return nil
}
