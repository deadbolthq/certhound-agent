package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	ScanPaths           []string `json:"ScanPaths"`
	ScanIntervalSeconds int      `json:"ScanIntervalSeconds"`
	LogPath             string   `json:"LogPath"`
	AWSEndpoint         string   `json:"AWSEndpoint"`
	TLSVerify           bool     `json:"TLSVerify"`
	MaxRetries          int      `json:"MaxRetries"`
	AgentName           string   `json:"AgentName"`
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

	// Optional: Set defaults if some fields are missing
	if cfg.ScanIntervalSeconds == 0 {
		cfg.ScanIntervalSeconds = 3600
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.AgentName == "" {
		cfg.AgentName = "CertSyncAgent"
	}

	return &cfg, nil
}

// Helper to get interval as Duration
func (c *Config) ScanInterval() time.Duration {
	return time.Duration(c.ScanIntervalSeconds) * time.Second
}
