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
	Renewal                  Renewal  `json:"Renewal"`
}

// Renewal configures ACME certificate auto-renewal. Disabled by default —
// users opt in by setting Enabled=true and adding at least one entry to Certs.
type Renewal struct {
	Enabled              bool           `json:"Enabled"`
	ACMEEmail            string         `json:"ACMEEmail"`
	ACMEDirectoryURL     string         `json:"ACMEDirectoryURL"`
	ChallengeType        string         `json:"ChallengeType"` // "http-01" (only one supported today)
	RenewalThresholdDays int            `json:"RenewalThresholdDays"`
	AccountKeyPath       string         `json:"AccountKeyPath"` // where the ACME account key lives
	Certs                []RenewalEntry `json:"Certs"`
}

// RenewalEntry describes one certificate the agent will renew.
//
// Output destinations are composable: set CertOutputPath/KeyOutputPath for a
// PEM file pair on disk, set WindowsCertStore to import into a Windows cert
// store (e.g. "LocalMachine\\MY"), or set both for redundancy. At least one
// destination must be set.
type RenewalEntry struct {
	Domains            []string `json:"Domains"`
	WebrootPath        string   `json:"WebrootPath"`
	CertOutputPath     string   `json:"CertOutputPath"`
	KeyOutputPath      string   `json:"KeyOutputPath"`
	WindowsCertStore   string   `json:"WindowsCertStore"`
	PostRenewalCommand string   `json:"PostRenewalCommand"`
}

// MatchesDomain returns true if this entry covers the given domain.
// Used to map a scanned cert back to its renewal config.
func (e RenewalEntry) MatchesDomain(domain string) bool {
	for _, d := range e.Domains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// Validate returns an error if the renewal config is enabled but incomplete.
// Called during startup when Renewal.Enabled is true.
func (r *Renewal) Validate() error {
	if !r.Enabled {
		return nil
	}
	if r.ACMEEmail == "" {
		return fmt.Errorf("renewal.ACMEEmail is required when renewal is enabled")
	}
	if r.ChallengeType != "" && r.ChallengeType != "http-01" {
		return fmt.Errorf("renewal.ChallengeType %q not supported (use http-01)", r.ChallengeType)
	}
	for i, entry := range r.Certs {
		if len(entry.Domains) == 0 {
			return fmt.Errorf("renewal.Certs[%d] has no domains", i)
		}
		if entry.WebrootPath == "" {
			return fmt.Errorf("renewal.Certs[%d] missing WebrootPath", i)
		}
		hasFilePair := entry.CertOutputPath != "" && entry.KeyOutputPath != ""
		hasPartialFilePair := (entry.CertOutputPath != "") != (entry.KeyOutputPath != "")
		hasStore := entry.WindowsCertStore != ""
		if hasPartialFilePair {
			return fmt.Errorf("renewal.Certs[%d] has CertOutputPath or KeyOutputPath set but not both", i)
		}
		if !hasFilePair && !hasStore {
			return fmt.Errorf("renewal.Certs[%d] must set either CertOutputPath+KeyOutputPath or WindowsCertStore", i)
		}
		if hasStore && runtime.GOOS != "windows" {
			return fmt.Errorf("renewal.Certs[%d] WindowsCertStore is only supported on Windows", i)
		}
	}
	return nil
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

	if err := cfg.Renewal.Validate(); err != nil {
		return nil, fmt.Errorf("invalid renewal config: %w", err)
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
		key, err := readKeyFile(path)
		if err == nil {
			return key, nil
		}
		// If the file exists but couldn't be read, it's a permissions problem.
		// Surface this immediately rather than printing a generic "no key found" message.
		if _, statErr := os.Stat(path); statErr == nil {
			return "", fmt.Errorf("API key file exists at %s but could not be read: %w\nTry running with sudo or as root.", path, err)
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
		Renewal: Renewal{
			Enabled:              false,
			ACMEDirectoryURL:     "https://acme-v02.api.letsencrypt.org/directory",
			ChallengeType:        "http-01",
			RenewalThresholdDays: 30,
			AccountKeyPath:       filepath.Join(platformConfigDir(), "acme-account.key"),
			Certs:                []RenewalEntry{},
		},
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
