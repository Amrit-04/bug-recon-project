package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()
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
		checkRate    float64
		checkTimeout time.Duration
	}{
		{
			name: "override rate",
			content: `rate: 20.0
`,
			wantError: false,
			checkRate: 20.0,
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
			content:   `rate: [unclosed`,
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
	content := `rate: 50.0
`
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Rate != 50.0 {
		t.Errorf("file should override default rate, got %f", cfg.Rate)
	}
	// Fields not in file should keep defaults
	if cfg.RatePerHost != 3.0 {
		t.Errorf("unset fields should keep default, got rate_per_host %f", cfg.RatePerHost)
	}
}

func TestFileConfigApplyKeepsExplicitFlags(t *testing.T) {
	rate := 1.0
	timeout := "5s"
	external := true
	posture := true
	fc := &FileConfig{
		Rate:          &rate,
		Timeout:       &timeout,
		External:      &external,
		VerifyPosture: &posture,
	}

	cfg := Defaults()
	changed := map[string]bool{"rate": true}
	fc.Apply(cfg, func(flagName string) bool { return changed[flagName] })

	if cfg.Rate != 10.0 {
		t.Errorf("an explicit --rate must win over the file, got %f", cfg.Rate)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("file timeout should apply when the flag is unset, got %v", cfg.Timeout)
	}
	if !cfg.External || !cfg.VerifyPosture {
		t.Errorf("file booleans should apply, got external=%v verify_posture=%v", cfg.External, cfg.VerifyPosture)
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
