package payload

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
	"github.com/google/uuid"
)

type Payload struct {
	// Payload classification
	PayloadID      string `json:"payload_id"`      // unique UUID per payload
	PayloadType    string `json:"payload_type"`     // "scan", "heartbeat", "error", "delta"
	PayloadVersion string `json:"payload_version"`

	// Agent identity
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	AgentVersion string `json:"agent_version"`
	ConfigHash   string `json:"config_hash"`

	// Org / tenant identity
	OrgID string `json:"org_id,omitempty"`

	// Host identity
	Host      string `json:"host"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Arch      string `json:"arch"`

	// Scan metadata
	Timestamp      string   `json:"timestamp"`
	ScanPaths      []string `json:"scan_paths"`
	ScanDurationMS int64    `json:"scan_duration_ms"`
	CertCount      int      `json:"cert_count"`
	ScanErrors     []string `json:"scan_errors,omitempty"`

	// Certificates (empty for heartbeat payloads)
	Certificates []scanner.CertInfo `json:"certificates"`
}

// NewPayload builds a scan payload with metadata + certs.
// scanStart is the time.Time recorded before scanning began, used to compute duration.
// scanErrors is a slice of non-fatal error strings collected during the scan.
func NewPayload(certs []scanner.CertInfo, cfg *config.Config, agentVersion string, agentID string, scanStart time.Time, scanErrors []string) *Payload {
	host, _ := os.Hostname()
	scanPaths := cfg.ScanPaths
	if runtime.GOOS == "windows" {
		scanPaths = cfg.ScanPathsWindows
	}
	if certs == nil {
		certs = []scanner.CertInfo{}
	}
	return &Payload{
		PayloadID:      uuid.New().String(),
		PayloadType:    "scan",
		PayloadVersion: cfg.PayloadVersion,
		AgentID:        agentID,
		AgentName:      cfg.AgentName,
		AgentVersion:   agentVersion,
		ConfigHash:     computeConfigHash(cfg),
		OrgID:          cfg.OrgID,
		Host:           host,
		OS:             runtime.GOOS,
		OSVersion:      getOSVersion(),
		Arch:           runtime.GOARCH,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ScanPaths:      scanPaths,
		ScanDurationMS: time.Since(scanStart).Milliseconds(),
		CertCount:      len(certs),
		ScanErrors:     scanErrors,
		Certificates:   certs,
	}
}

// NewHeartbeatPayload builds a lightweight heartbeat payload with no cert data.
func NewHeartbeatPayload(cfg *config.Config, agentVersion string, agentID string) *Payload {
	host, _ := os.Hostname()
	return &Payload{
		PayloadID:      uuid.New().String(),
		PayloadType:    "heartbeat",
		PayloadVersion: cfg.PayloadVersion,
		AgentID:        agentID,
		AgentName:      cfg.AgentName,
		AgentVersion:   agentVersion,
		ConfigHash:     computeConfigHash(cfg),
		OrgID:          cfg.OrgID,
		Host:           host,
		OS:             runtime.GOOS,
		OSVersion:      getOSVersion(),
		Arch:           runtime.GOARCH,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Certificates:   []scanner.CertInfo{},
	}
}

// computeConfigHash returns a SHA-256 hash of the serialized config.
// This lets the backend detect when an agent's configuration changed between runs.
func computeConfigHash(cfg *config.Config) string {
	data, err := json.Marshal(cfg)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum)
}

// getOSVersion returns a best-effort OS version string.
func getOSVersion() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("cmd", "/c", "ver").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	case "darwin":
		out, err := exec.Command("sw_vers", "-productVersion").Output()
		if err == nil {
			return fmt.Sprintf("macOS %s", strings.TrimSpace(string(out)))
		}
	default:
		out, err := exec.Command("uname", "-r").Output()
		if err == nil {
			return fmt.Sprintf("Linux %s", strings.TrimSpace(string(out)))
		}
	}
	return "unknown"
}
