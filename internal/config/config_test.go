package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
	if cfg.Concurrency != 25 {
		t.Errorf("expected concurrency 25, got %d", cfg.Concurrency)
	}
	if cfg.Rate != 10.0 {
		t.Errorf("expected rate 10.0, got %f", cfg.Rate)
	}
	if cfg.MaxBodyBytes != 1024*1024 {
		t.Errorf("expected max body 1MB, got %d", cfg.MaxBodyBytes)
	}
}

func TestLoadFromFile(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		wantError    bool
		checkConcur  int
		checkRate    float64
		checkTimeout time.Duration
	}{
		{
			name: "override concurrency",
			content: `concurrency: 50
rate: 20.0
`,
			wantError:   false,
			checkConcur: 50,
			checkRate:   20.0,
		},
		{
			name: "override timeout",
			content: `timeout: "60s"
`,
			wantError:    false,
			checkTimeout: 60 * time.Second,
		},
		{
			name:      "invalid YAML",
			content:   `concurrency: [unclosed`,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile := filepath.Join(t.TempDir(), ".scoutr.yaml")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			cfg, err := LoadFromFile(tmpFile)
			if (err != nil) != tt.wantError {
				t.Errorf("LoadFromFile() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if tt.wantError {
				return
			}

			if tt.checkConcur > 0 && cfg.Concurrency != tt.checkConcur {
				t.Errorf("expected concurrency %d, got %d", tt.checkConcur, cfg.Concurrency)
			}
			if tt.checkRate > 0 && cfg.Rate != tt.checkRate {
				t.Errorf("expected rate %f, got %f", tt.checkRate, cfg.Rate)
			}
			if tt.checkTimeout > 0 && cfg.Timeout != tt.checkTimeout {
				t.Errorf("expected timeout %v, got %v", tt.checkTimeout, cfg.Timeout)
			}
		})
	}
}

func TestPrecedence(t *testing.T) {
	// File config should override defaults
	tmpFile := filepath.Join(t.TempDir(), ".scoutr.yaml")
	content := `concurrency: 100
rate: 50.0
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Concurrency != 100 {
		t.Errorf("file should override default concurrency, got %d", cfg.Concurrency)
	}
	if cfg.Rate != 50.0 {
		t.Errorf("file should override default rate, got %f", cfg.Rate)
	}
	// Fields not in file should keep defaults
	if cfg.RatePerHost != 3.0 {
		t.Errorf("unset fields should keep default, got rate_per_host %f", cfg.RatePerHost)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(*Config)
		wantError bool
	}{
		{
			name:      "valid config",
			modify:    func(c *Config) {},
			wantError: false,
		},
		{
			name:      "zero concurrency",
			modify:    func(c *Config) { c.Concurrency = 0 },
			wantError: true,
		},
		{
			name:      "negative rate",
			modify:    func(c *Config) { c.Rate = -1 },
			wantError: true,
		},
		{
			name:      "zero timeout",
			modify:    func(c *Config) { c.Timeout = 0 },
			wantError: true,
		},
		{
			name:      "zero max body",
			modify:    func(c *Config) { c.MaxBodyBytes = 0 },
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
