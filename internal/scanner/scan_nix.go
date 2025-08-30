//go:build !windows
// +build !windows

/*
Package scanner provides utilities for scanning X.509 certificates.

This file contains a stub implementation of ScanWindowsCertStore for non-Windows
platforms. It ensures that the scanner package can compile and run on Linux, macOS,
and other OSes where the Windows certificate store does not exist.

Author: Will Keel
Date: 2025-08-27
*/

package scanner

import "github.com/keelw/certsync-agent/internal/config"

/*
ScanWindowsCertStore is a stub implementation for non-Windows platforms.

Since non-Windows systems do not have a Windows certificate store, this function
simply returns nil for both the certificate slice and the error.

Returns:

	[]CertInfo - nil, as no certificates are available from a Windows store
	error      - nil, no error occurs
*/
func ScanWindowsCertStore(cfg *config.Config) ([]CertInfo, error) {
	return nil, nil
}
