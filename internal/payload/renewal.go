package payload

import (
	"os"
	"runtime"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/deadbolthq/certhound-agent/internal/renewal"
	"github.com/deadbolthq/certhound-agent/internal/scanner"
	"github.com/google/uuid"
)

// RenewalPayload reports the outcome of one or more renewal attempts.
// Same envelope shape as Payload so the backend ingest route can dispatch on
// payload_type, but carries renewal.Result instead of cert scan data.
type RenewalPayload struct {
	PayloadID      string `json:"payload_id"`
	PayloadType    string `json:"payload_type"`
	PayloadVersion string `json:"payload_version"`

	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	AgentVersion string `json:"agent_version"`

	OrgID string `json:"org_id,omitempty"`

	Host      string `json:"host"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Arch      string `json:"arch"`

	Timestamp string           `json:"timestamp"`
	Results   []renewal.Result `json:"renewal_results"`
}

// NewRenewalPayload wraps a batch of renewal attempts into a payload envelope.
// Use a RenewalPayload rather than shoe-horning results into Payload so the
// backend can route renewal events to their own handler without inspecting the
// body twice.
func NewRenewalPayload(results []renewal.Result, cfg *config.Config, agentVersion string, agentID string) *RenewalPayload {
	host, _ := os.Hostname()
	if results == nil {
		results = []renewal.Result{}
	}
	return &RenewalPayload{
		PayloadID:      uuid.New().String(),
		PayloadType:    "renewal",
		PayloadVersion: cfg.PayloadVersion,
		AgentID:        agentID,
		AgentName:      cfg.AgentName,
		AgentVersion:   agentVersion,
		OrgID:          cfg.OrgID,
		Host:           host,
		OS:             runtime.GOOS,
		OSVersion:      getOSVersion(),
		Arch:           runtime.GOARCH,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Results:        results,
	}
}

// Explicit compile-time assertion that our two payload types don't collide
// on the scanner import (unused otherwise). Lets go vet catch a future refactor
// that accidentally drops the scanner dep from this package.
var _ = scanner.CertInfo{}
