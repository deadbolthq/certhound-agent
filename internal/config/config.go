package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"
)

// Config defines agent configuration
type Config struct {
	ScanPaths             []string `json:"ScanPaths"`
	ScanPathsWindows      []string `json:"ScanPathsWindows"`
	ScanIntervalSeconds   int      `json:"ScanIntervalSeconds"`
	ExpiringThresholdDays int      `json:"ExpiringThresholdDays"`
	LogPath               string   `json:"LogPath"`
	Verbose               bool     `json:"Verbose"`
	LogLevel              string   `json:"LogLevel"`
	AWSEndpoint           string   `json:"AWSEndpoint"`
	TLSVerify             bool     `json:"TLSVerify"`
	MaxRetries            int      `json:"MaxRetries"`
	AgentName             string   `json:"AgentName"`
	IncludeIPAddresses    bool     `json:"IncludeIPAddresses"`
	IncludeSelfSigned     bool     `json:"IncludeSelfSigned"`
	PayloadVersion        string   `json:"PayloadVersion"`
}

// LoadConfig reads a JSON config file and returns a Config struct
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Apply defaults for missing or zero values
	if cfg.ScanIntervalSeconds <= 0 {
		cfg.ScanIntervalSeconds = 3600
	}
	if cfg.ExpiringThresholdDays <= 0 {
		cfg.ExpiringThresholdDays = 30
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.AgentName == "" {
		cfg.AgentName = "certhound-agent"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}
	if cfg.PayloadVersion == "" {
		cfg.PayloadVersion = "1.0"
	}
	if cfg.LogPath == "" {
		if runtime.GOOS == "windows" {
			cfg.LogPath = `C:\ProgramData\CertHound\logs`
		} else {
			cfg.LogPath = "/var/log/certhound"
		}
	}

	return &cfg, nil
}

// DefaultConfig returns a Config with sensible defaults and OS-appropriate scan paths.
// Used when no config file is provided.
func DefaultConfig() *Config {
	cfg := &Config{
		ScanIntervalSeconds:   3600,
		ExpiringThresholdDays: 30,
		MaxRetries:            3,
		AgentName:             "certhound-agent",
		LogLevel:              "INFO",
		PayloadVersion:        "1.0",
		TLSVerify:             true,
	}
	switch runtime.GOOS {
	case "windows":
		cfg.LogPath = `C:\ProgramData\CertHound\logs`
		cfg.ScanPathsWindows = []string{
			`C:\Windows\System32\`,
			`C:\ProgramData\SSL\`,
		}
	case "darwin":
		cfg.LogPath = "/var/log/certhound"
		cfg.ScanPaths = []string{
			"/etc/ssl/certs",
			"/usr/local/share/ca-certificates",
			"/Library/Keychains",
		}
	default:
		cfg.LogPath = "/var/log/certhound"
		cfg.ScanPaths = []string{
			"/etc/ssl/certs",
			"/etc/pki/tls/certs",
			"/usr/local/share/ca-certificates",
			"/etc/letsencrypt/live",
		}
	}
	return cfg
}

// ScanInterval returns the scan interval as a time.Duration
func (c *Config) ScanInterval() time.Duration {
	return time.Duration(c.ScanIntervalSeconds) * time.Second
}
