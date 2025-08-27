//go:build !windows
// +build !windows

package scanner

// ScanWindowsCertStore is a stub on non-Windows platforms
func ScanWindowsCertStore() ([]CertInfo, error) {
	return nil, nil
}
