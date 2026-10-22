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

	// Concurrency & Performance
	Concurrency  int
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

	// Checks
	Checks     []string // If empty, run all checks
	SkipChecks []string
}

// FileConfig is the structure of .scoutr.yaml config files.
type FileConfig struct {
	Concurrency  *int              `yaml:"concurrency,omitempty"`
	Rate         *float64          `yaml:"rate,omitempty"`
	RatePerHost  *float64          `yaml:"rate_per_host,omitempty"`
	Timeout      *string           `yaml:"timeout,omitempty"` // e.g., "30s"
	MaxBodyBytes *int64            `yaml:"max_body_bytes,omitempty"`
	UserAgent    *string           `yaml:"user_agent,omitempty"`
	Headers      map[string]string `yaml:"headers,omitempty"`
	Checks       []string          `yaml:"checks,omitempty"`
	SkipChecks   []string          `yaml:"skip_checks,omitempty"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Concurrency:  25,
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	cfg := Defaults()
	applyFileConfig(cfg, &fc)
	return cfg, nil
}

// applyFileConfig merges file config into the base config (file overrides defaults).
func applyFileConfig(cfg *Config, fc *FileConfig) {
	if fc.Concurrency != nil {
		cfg.Concurrency = *fc.Concurrency
	}
	if fc.Rate != nil {
		cfg.Rate = *fc.Rate
	}
	if fc.RatePerHost != nil {
		cfg.RatePerHost = *fc.RatePerHost
	}
	if fc.Timeout != nil {
		d, err := time.ParseDuration(*fc.Timeout)
		if err == nil {
			cfg.Timeout = d
		}
	}
	if fc.MaxBodyBytes != nil {
		cfg.MaxBodyBytes = *fc.MaxBodyBytes
	}
	if fc.UserAgent != nil {
		cfg.UserAgent = *fc.UserAgent
	}
	if fc.Headers != nil {
		cfg.Headers = fc.Headers
	}
	if len(fc.Checks) > 0 {
		cfg.Checks = fc.Checks
	}
	if len(fc.SkipChecks) > 0 {
		cfg.SkipChecks = fc.SkipChecks
	}
}

// Validate checks that the config is valid.
func (c *Config) Validate() error {
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}
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
