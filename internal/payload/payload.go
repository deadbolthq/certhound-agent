package payload

import (
	"os"
	"runtime"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
)

type Payload struct {
	Host           string             `json:"host"`
	OS             string             `json:"os"`
	AgentName      string             `json:"agent_name"`
	AgentVersion   string             `json:"agent_version"`
	PayloadVersion string             `json:"payload_version"`
	Timestamp      string             `json:"timestamp"`
	Certificates   []scanner.CertInfo `json:"certificates"`
	IncludeIP      bool               `json:"include_ip_addresses,omitempty"`
}

// NewPayload builds a payload with metadata + certs
func NewPayload(certs []scanner.CertInfo, cfg *config.Config, agentVersion string) *Payload {
	host, _ := os.Hostname()
	return &Payload{
		Host:           host,
		OS:             runtime.GOOS,
		AgentName:      cfg.AgentName,
		AgentVersion:   agentVersion,
		PayloadVersion: cfg.PayloadVersion,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Certificates:   certs,
		IncludeIP:      cfg.IncludeIPAddresses,
	}
}
