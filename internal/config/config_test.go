package config

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestDefaultConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ScanIntervalSeconds != 86400 {
		t.Errorf("ScanIntervalSeconds: got %d, want 86400", cfg.ScanIntervalSeconds)
	}
	if cfg.HeartbeatIntervalSeconds != 3600 {
		t.Errorf("HeartbeatIntervalSeconds: got %d, want 3600", cfg.HeartbeatIntervalSeconds)
	}
	if cfg.ExpiringThresholdDays != 30 {
		t.Errorf("ExpiringThresholdDays: got %d, want 30", cfg.ExpiringThresholdDays)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries: got %d, want 3", cfg.MaxRetries)
	}
	if cfg.AgentName != "certhound-agent" {
		t.Errorf("AgentName: got %q, want %q", cfg.AgentName, "certhound-agent")
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel: got %q, want INFO", cfg.LogLevel)
	}
	if cfg.PayloadVersion != "1.0" {
		t.Errorf("PayloadVersion: got %q, want 1.0", cfg.PayloadVersion)
	}
	if !cfg.TLSVerify {
		t.Error("TLSVerify should default to true")
	}
	if cfg.LogPath == "" {
		t.Error("LogPath should not be empty")
	}
}

func TestDefaultConfig_OSScanPaths(t *testing.T) {
	cfg := DefaultConfig()
	switch runtime.GOOS {
	case "windows":
		if len(cfg.ScanPathsWindows) == 0 {
			t.Error("ScanPathsWindows should be non-empty on Windows")
		}
	default:
		if len(cfg.ScanPaths) == 0 {
			t.Error("ScanPaths should be non-empty on non-Windows")
		}
	}
}

func TestScanInterval(t *testing.T) {
	cfg := &Config{ScanIntervalSeconds: 120}
	if cfg.ScanInterval() != 120*time.Second {
		t.Errorf("ScanInterval: got %v, want 2m0s", cfg.ScanInterval())
	}
}

func writeConfigFile(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "config*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestLoadConfig_ZeroValueFallbacks(t *testing.T) {
	// Write a minimal config with all zero values
	path := writeConfigFile(t, map[string]any{})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.ScanIntervalSeconds != 86400 {
		t.Errorf("ScanIntervalSeconds fallback: got %d, want 86400", cfg.ScanIntervalSeconds)
	}
	if cfg.ExpiringThresholdDays != 30 {
		t.Errorf("ExpiringThresholdDays fallback: got %d, want 30", cfg.ExpiringThresholdDays)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries fallback: got %d, want 3", cfg.MaxRetries)
	}
	if cfg.AgentName != "certhound-agent" {
		t.Errorf("AgentName fallback: got %q", cfg.AgentName)
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel fallback: got %q", cfg.LogLevel)
	}
	if cfg.PayloadVersion != "1.0" {
		t.Errorf("PayloadVersion fallback: got %q", cfg.PayloadVersion)
	}
	if cfg.LogPath == "" {
		t.Errorf("LogPath fallback: got empty string")
	}
}

func TestLoadConfig_ExplicitValues(t *testing.T) {
	path := writeConfigFile(t, map[string]any{
		"ScanIntervalSeconds":   600,
		"ExpiringThresholdDays": 14,
		"MaxRetries":            5,
		"AgentName":             "my-agent",
		"LogLevel":              "DEBUG",
		"PayloadVersion":        "2.0",
		"LogPath":               "/var/log/certhound",
		"TLSVerify":             false,
	})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.ScanIntervalSeconds != 600 {
		t.Errorf("ScanIntervalSeconds: got %d", cfg.ScanIntervalSeconds)
	}
	if cfg.ExpiringThresholdDays != 14 {
		t.Errorf("ExpiringThresholdDays: got %d", cfg.ExpiringThresholdDays)
	}
	if cfg.AgentName != "my-agent" {
		t.Errorf("AgentName: got %q", cfg.AgentName)
	}
	if cfg.TLSVerify {
		t.Error("TLSVerify: expected false")
	}
	if cfg.LogPath != "/var/log/certhound" {
		t.Errorf("LogPath: got %q", cfg.LogPath)
	}
}

func TestLoadConfig_InheritsScanPaths(t *testing.T) {
	// Empty config file should still have OS-appropriate scan paths from DefaultConfig
	path := writeConfigFile(t, map[string]any{})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	switch runtime.GOOS {
	case "windows":
		if len(cfg.ScanPathsWindows) == 0 {
			t.Error("ScanPathsWindows should be inherited from defaults when not set in config")
		}
	default:
		if len(cfg.ScanPaths) == 0 {
			t.Error("ScanPaths should be inherited from defaults when not set in config")
		}
	}
}

func TestLoadConfig_ExplicitScanPathsOverride(t *testing.T) {
	path := writeConfigFile(t, map[string]any{
		"ScanPaths": []string{"/custom/path"},
	})
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.ScanPaths) != 1 || cfg.ScanPaths[0] != "/custom/path" {
		t.Errorf("ScanPaths: got %v, want [/custom/path]", cfg.ScanPaths)
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("not json")
	f.Close()

	_, err = LoadConfig(f.Name())
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
