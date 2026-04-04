//go:build !windows

package main

import "context"

func isWindowsService() bool { return false }

func runAsService(_ func(ctx context.Context)) {
	// Never called on non-Windows platforms.
	panic("runAsService called on non-Windows platform")
}
