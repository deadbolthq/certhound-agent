package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	AWSEndpoint              string   `json:"AWSEndpoint"`
	APIKey                   string   `json:"-"` // Never read from config JSON — use env var or key file
	TLSVerify                bool     `json:"TLSVerify"`
	MaxRetries               int      `json:"MaxRetries"`
	AgentName                string   `json:"AgentName"`
	IncludeIPAddresses       bool     `json:"IncludeIPAddresses"`
	IncludeSelfSigned        bool     `json:"IncludeSelfSigned"`
	PayloadVersion           string   `json:"PayloadVersion"`
	OrgID                    string   `json:"OrgID"`
	HeartbeatIntervalSeconds int      `json:"HeartbeatIntervalSeconds"`
	AutoUpdate               bool     `json:"AutoUpdate"`
	UpdateCheckURL           string   `json:"UpdateCheckURL"`
}

// platformConfigDir returns the OS-appropriate directory for CertHound config and key files.
func platformConfigDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\CertHound`
	}
	return "/etc/certhound"
}

// Provision writes the API key and a default config file to the platform config directory.
// Called once by the installer via --provision. Safe to re-run — overwrites existing files.
func Provision(apiKey, endpoint string) error {
	dir := platformConfigDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config dir %s: %w", dir, err)
	}

	// Write API key (mode 0600 — readable only by root/SYSTEM)
	keyPath := filepath.Join(dir, "api.key")
	if err := os.WriteFile(keyPath, []byte(strings.TrimSpace(apiKey)+"\n"), 0600); err != nil {
		return fmt.Errorf("writing api key to %s: %w", keyPath, err)
	}
	fmt.Printf("  API key written to: %s\n", keyPath)

	// Write config with endpoint set; all other values are defaults
	cfg := DefaultConfig()
	cfg.AWSEndpoint = endpoint
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("writing config to %s: %w", configPath, err)
	}
	fmt.Printf("  Config written to:  %s\n", configPath)

	return nil
}

// LoadConfig reads a JSON config file and returns a Config struct
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	return cfg, nil
}

// ResolveAPIKey searches for the API key in the following order:
//
//  1. CERTHOUND_API_KEY environment variable
//  2. Explicit key file path (from --api-key-file flag)
//  3. Platform-specific default key file locations:
//     - Linux/macOS: /etc/certhound/api.key, ~/.certhound/api.key
//     - Windows:     C:\ProgramData\CertHound\api.key, %USERPROFILE%\.certhound\api.key
//
// Returns an error describing all locations checked if no key is found.
func ResolveAPIKey(explicitPath string) (string, error) {
	// 1. Environment variable (highest priority)
	if key := os.Getenv("CERTHOUND_API_KEY"); key != "" {
		return strings.TrimSpace(key), nil
	}

	// 2. Explicit key file path from flag
	if explicitPath != "" {
		key, err := readKeyFile(explicitPath)
		if err != nil {
			return "", fmt.Errorf("could not read API key file %q: %w", explicitPath, err)
		}
		return key, nil
	}

	// 3. Platform-specific default locations
	candidates := defaultKeyFilePaths()
	for _, path := range candidates {
		if key, err := readKeyFile(path); err == nil {
			return key, nil
		}
	}

	return "", fmt.Errorf(
		"no API key found. Provide one using any of these methods:\n\n"+
			"  1. Environment variable:\n"+
			"       export CERTHOUND_API_KEY=your-key-here\n\n"+
			"  2. Key file (flag):\n"+
			"       certhound-agent --api-key-file /path/to/api.key\n\n"+
			"  3. Key file (default location):\n"+
			"       %s\n"+
			"       File should contain the API key as a single line, nothing else.\n",
		candidates[0],
	)
}

func readKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("key file %q is empty", path)
	}
	return key, nil
}

func defaultKeyFilePaths() []string {
	switch runtime.GOOS {
	case "windows":
		paths := []string{`C:\ProgramData\CertHound\api.key`}
		if home := os.Getenv("USERPROFILE"); home != "" {
			paths = append(paths, home+`\.certhound\api.key`)
		}
		return paths
	default:
		paths := []string{"/etc/certhound/api.key"}
		if home := os.Getenv("HOME"); home != "" {
			paths = append(paths, home+"/.certhound/api.key")
		}
		return paths
	}
}

// DefaultConfig returns a Config with sensible defaults and OS-appropriate scan paths.
// Used when no config file is provided.
func DefaultConfig() *Config {
	cfg := &Config{
		ScanIntervalSeconds:      86400, // daily
		HeartbeatIntervalSeconds: 3600,  // hourly
		ExpiringThresholdDays:    30,
		MaxRetries:               3,
		AgentName:                "certhound-agent",
		LogLevel:                 "INFO",
		PayloadVersion:           "1.0",
		TLSVerify:                true,
		AutoUpdate:               true,
		UpdateCheckURL:           "https://api.github.com/repos/deadbolthq/certhound-agent/releases/latest",
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

// ScanInterval returns the scan interval as a time.Duration.
func (c *Config) ScanInterval() time.Duration {
	return time.Duration(c.ScanIntervalSeconds) * time.Second
}

// HeartbeatInterval returns the heartbeat interval as a time.Duration.
func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSeconds) * time.Second
}
