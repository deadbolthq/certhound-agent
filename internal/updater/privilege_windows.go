//go:build windows

package updater

import (
	"os"
	"path/filepath"
)

// isPrivileged checks whether the process has administrator/SYSTEM privileges
// by attempting to write to a protected directory.
func isPrivileged() bool {
	testPath := filepath.Join(os.Getenv("SYSTEMROOT"), ".certhound-priv-check")
	f, err := os.Create(testPath)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(testPath)
	return true
}
