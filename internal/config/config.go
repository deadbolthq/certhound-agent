package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config defines agent configuration
type Config struct {
	ScanPaths           []string `json:"ScanPaths"`
	ScanPathsWindows    []string `json:"ScanPathsWindows"`
	ScanIntervalSeconds int      `json:"ScanIntervalSeconds"`
	LogPath             string   `json:"LogPath"`
	Verbose             bool     `json:"Verbose"`
	LogLevel            string   `json:"LogLevel"`
	AWSEndpoint         string   `json:"AWSEndpoint"`
	TLSVerify           bool     `json:"TLSVerify"`
	MaxRetries          int      `json:"MaxRetries"`
	AgentName           string   `json:"AgentName"`
	IncludeIPAddresses  bool     `json:"IncludeIPAddresses"`
	IncludeSelfSigned   bool     `json:"IncludeSelfSigned"`
	PayloadVersion      string   `json:"PayloadVersion"`
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

	// Set sensible defaults if missing
	if cfg.ScanIntervalSeconds == 0 {
		cfg.ScanIntervalSeconds = 3600 // default 1 hour
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.AgentName == "" {
		cfg.AgentName = "CertSyncAgent"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.PayloadVersion == "" {
		cfg.PayloadVersion = "1.0"
	}

	return &cfg, nil
}

// ScanInterval returns the scan interval as a time.Duration
func (c *Config) ScanInterval() time.Duration {
	return time.Duration(c.ScanIntervalSeconds) * time.Second
}
