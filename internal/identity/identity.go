package identity

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

// agentIDPath returns the platform-appropriate path for the persisted agent ID file.
func agentIDPath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\CertHound\agent-id`
	}
	return "/etc/certhound/agent-id"
}

// GetOrCreate returns the persisted agent ID, creating and saving a new UUID if none exists.
func GetOrCreate() string {
	path := agentIDPath()

	if data, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}

	id := uuid.New().String()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err == nil {
		os.WriteFile(path, []byte(id), 0644)
	}
	return id
}
