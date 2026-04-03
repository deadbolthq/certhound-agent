package payload

import (
	"runtime"
	"strings"
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

	pl := NewPayload(certs, cfg, "1.2.3", "test-agent-id", time.Now(), nil)

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
	if pl.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if pl.CertCount != 1 {
		t.Errorf("CertCount: got %d, want 1", pl.CertCount)
	}
	if len(pl.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(pl.Certificates))
	}
	if pl.AgentID != "test-agent-id" {
		t.Errorf("AgentID: got %q, want %q", pl.AgentID, "test-agent-id")
	}
	if pl.PayloadType != "scan" {
		t.Errorf("PayloadType: got %q, want %q", pl.PayloadType, "scan")
	}
	if pl.PayloadID == "" {
		t.Error("PayloadID should be a UUID, got empty string")
	}
	if !strings.HasPrefix(pl.ConfigHash, "sha256:") {
		t.Errorf("ConfigHash: got %q, want sha256:... prefix", pl.ConfigHash)
	}
}

func TestNewPayload_TimestampFormat(t *testing.T) {
	cfg := &config.Config{AgentName: "a", PayloadVersion: "1.0"}
	pl := NewPayload(nil, cfg, "dev", "test-agent-id", time.Now(), nil)

	_, err := time.Parse(time.RFC3339, pl.Timestamp)
	if err != nil {
		t.Errorf("Timestamp %q is not RFC3339: %v", pl.Timestamp, err)
	}
}

func TestNewPayload_EmptyCerts(t *testing.T) {
	cfg := &config.Config{AgentName: "a", PayloadVersion: "1.0"}
	pl := NewPayload(nil, cfg, "dev", "test-agent-id", time.Now(), nil)
	if pl.Certificates == nil {
		t.Error("Certificates should be empty slice, not nil (serializes as [] not null)")
	}
	if len(pl.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(pl.Certificates))
	}
}

func TestNewHeartbeatPayload(t *testing.T) {
	cfg := &config.Config{
		AgentName:      "test-agent",
		PayloadVersion: "1.0",
		OrgID:          "acme-corp",
	}
	pl := NewHeartbeatPayload(cfg, "1.2.3", "hb-agent-id")

	if pl.PayloadType != "heartbeat" {
		t.Errorf("PayloadType: got %q, want %q", pl.PayloadType, "heartbeat")
	}
	if pl.PayloadID == "" {
		t.Error("PayloadID should be a UUID, got empty string")
	}
	if pl.OrgID != "acme-corp" {
		t.Errorf("OrgID: got %q, want %q", pl.OrgID, "acme-corp")
	}
	if !strings.HasPrefix(pl.ConfigHash, "sha256:") {
		t.Errorf("ConfigHash: got %q, want sha256:... prefix", pl.ConfigHash)
	}
	if pl.Certificates == nil || len(pl.Certificates) != 0 {
		t.Errorf("Heartbeat should have empty (not nil) Certificates slice")
	}
}

func TestPayloadID_Unique(t *testing.T) {
	cfg := &config.Config{AgentName: "a", PayloadVersion: "1.0"}
	pl1 := NewPayload(nil, cfg, "dev", "agent-1", time.Now(), nil)
	pl2 := NewPayload(nil, cfg, "dev", "agent-1", time.Now(), nil)
	if pl1.PayloadID == pl2.PayloadID {
		t.Error("each payload should get a unique PayloadID")
	}
}
