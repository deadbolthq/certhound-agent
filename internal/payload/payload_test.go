package payload

import (
	"runtime"
	"testing"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
)

func TestNewPayload_Fields(t *testing.T) {
	cfg := &config.Config{
		AgentName:          "test-agent",
		PayloadVersion:     "1.0",
		IncludeIPAddresses: true,
	}
	certs := []scanner.CertInfo{
		{Subject: "CN=example.com", DNSNames: []string{"example.com"}},
	}

	pl := NewPayload(certs, cfg, "1.2.3", "test-agent-id")

	if pl.AgentName != "test-agent" {
		t.Errorf("AgentName: got %q", pl.AgentName)
	}
	if pl.AgentVersion != "1.2.3" {
		t.Errorf("AgentVersion: got %q", pl.AgentVersion)
	}
	if pl.PayloadVersion != "1.0" {
		t.Errorf("PayloadVersion: got %q", pl.PayloadVersion)
	}
	if pl.OS != runtime.GOOS {
		t.Errorf("OS: got %q, want %q", pl.OS, runtime.GOOS)
	}
	if pl.Host == "" {
		t.Error("Host should not be empty")
	}
	if pl.IncludeIP != true {
		t.Error("IncludeIP should reflect cfg.IncludeIPAddresses")
	}
	if len(pl.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(pl.Certificates))
	}
	if pl.AgentID != "test-agent-id" {
		t.Errorf("AgentID: got %q, want %q", pl.AgentID, "test-agent-id")
	}
}

func TestNewPayload_TimestampFormat(t *testing.T) {
	cfg := &config.Config{AgentName: "a", PayloadVersion: "1.0"}
	pl := NewPayload(nil, cfg, "dev", "test-agent-id")

	_, err := time.Parse(time.RFC3339, pl.Timestamp)
	if err != nil {
		t.Errorf("Timestamp %q is not RFC3339: %v", pl.Timestamp, err)
	}
}

func TestNewPayload_EmptyCerts(t *testing.T) {
	cfg := &config.Config{AgentName: "a", PayloadVersion: "1.0"}
	pl := NewPayload(nil, cfg, "dev", "test-agent-id")
	if pl.Certificates != nil {
		t.Errorf("expected nil Certificates slice for nil input, got %v", pl.Certificates)
	}
}
