package payload

import (
	"os"
	"runtime"
	"time"

	"github.com/keelw/certsync-agent/internal/scanner"
)

type Payload struct {
	Host         string             `json:"host"`
	OS           string             `json:"os"`
	AgentVersion string             `json:"agent_version"`
	Timestamp    string             `json:"timestamp"`
	Certificates []scanner.CertInfo `json:"certificates"`
}

// NewPayload builds a payload with metadata + certs
func NewPayload(certs []scanner.CertInfo, agentVersion string) *Payload {
	host, _ := os.Hostname()
	return &Payload{
		Host:         host,
		OS:           runtime.GOOS,
		AgentVersion: agentVersion,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Certificates: certs,
	}
}
