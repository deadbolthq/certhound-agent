//go:build !windows

package updater

import "os"

// isPrivileged returns true if running as root (uid 0).
func isPrivileged() bool {
	return os.Getuid() == 0
}
