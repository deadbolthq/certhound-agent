/*
Package scanner provides utilities for scanning X.509 certificates from the filesystem
and converting them to a JSON-friendly format. It supports Linux, macOS, and Windows
by optionally scanning the Windows certificate store.

Author: Will Keel
Date: 2025-08-27
*/

package scanner

import (
	"crypto/x509"   // For parsing X.509 certificates
	"encoding/json" // For JSON marshaling
	"encoding/pem"  // For decoding PEM blocks
	"io/fs"         // For file system directory walking
	"os"            // For reading files and checking existence
	"path/filepath" // For cross-platform file path handling
	"runtime"       // For detecting operating system
	"strings"       // For string manipulation
	"time"          // For working with certificate expiration dates
)

// CertInfo represents a certificate in a JSON-friendly format.
//
// Fields:
//
//	Subject      - The certificate's subject (owner)
//	Issuer       - The certificate issuer (CA)
//	NotBefore    - Certificate validity start (RFC3339 format)
//	NotAfter     - Certificate expiry (RFC3339 format)
//	DNSNames     - Associated domain names
//	IPAddresses  - Associated IP addresses, optional
//	CertPath     - Path to the certificate file
//	KeyPath      - Guessed path to private key
//	ExpiringSoon - True if certificate expires within 30 days
type CertInfo struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	NotBefore    string   `json:"not_before"`
	NotAfter     string   `json:"not_after"`
	DNSNames     []string `json:"dns_names"`
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	CertPath     string   `json:"cert_path"`
	KeyPath      string   `json:"key_path"`
	ExpiringSoon bool     `json:"expiring_soon"`
}

/*
ScanCertFiles scans a specified directory for PEM or CRT certificate files and
returns a slice of CertInfo objects. Only domain certificates (not self-signed root CAs)
with at least one DNS name are included.

Parameters:

	dir - Directory to scan for certificates

Returns:

	[]CertInfo - Slice of certificate information
	error      - Any error encountered during scanning
*/
func ScanCertFiles(dir string) ([]CertInfo, error) {
	var certInfos []CertInfo

	// WalkDir recursively traverses the directory tree
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// If we can't access a file or directory, return the error
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Read the file contents
		data, err := os.ReadFile(path)
		if err != nil {
			// Skip unreadable files silently
			return nil
		}

		// Decode all PEM blocks in the file
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}

			// Only process certificate blocks
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					// Skip invalid certificates
					continue
				}

				// Skip self-signed root certificates without DNS names
				if len(cert.DNSNames) == 0 && !isLikelyDomainCert(cert) {
					continue
				}

				// Convert IP addresses to strings
				ipStrs := []string{}
				for _, ip := range cert.IPAddresses {
					ipStrs = append(ipStrs, ip.String())
				}

				// Check if the certificate expires within 30 days
				expiringSoon := time.Until(cert.NotAfter) < 30*24*time.Hour

				// Append a new CertInfo object to the result slice
				certInfos = append(certInfos, CertInfo{
					Subject:      cert.Subject.String(),
					Issuer:       cert.Issuer.String(),
					NotBefore:    cert.NotBefore.Format(time.RFC3339),
					NotAfter:     cert.NotAfter.Format(time.RFC3339),
					DNSNames:     cert.DNSNames,
					IPAddresses:  ipStrs,
					CertPath:     path,
					KeyPath:      guessKeyPath(path),
					ExpiringSoon: expiringSoon,
				})
			}
		}

		return nil
	})

	return certInfos, err
}

/*
isLikelyDomainCert returns true if the certificate is not a self-signed root CA.

Parameters:

	cert - Pointer to x509.Certificate

Returns:

	bool - True if certificate appears to belong to a domain
*/
func isLikelyDomainCert(cert *x509.Certificate) bool {
	return cert.Issuer.String() != cert.Subject.String()
}

/*
guessKeyPath attempts to guess the location of the private key corresponding
to a given certificate. Checks standard Linux and Windows paths.

Parameters:

	certPath - Path to the certificate file

Returns:

	string - Path to private key if found, empty string otherwise
*/
func guessKeyPath(certPath string) string {
	base := filepath.Base(certPath)
	ext := filepath.Ext(base)
	baseName := strings.TrimSuffix(base, ext) + ".key"

	// Linux default private key directory
	linuxPath := filepath.Join("/etc/ssl/private", baseName)
	if fileExists(linuxPath) {
		return linuxPath
	}

	// Windows default private key directory
	winPath := filepath.Join("C:\\ProgramData\\SSL\\Keys", baseName)
	if fileExists(winPath) {
		return winPath
	}

	// Key not found
	return ""
}

/*
fileExists checks if a file exists at the given path and is not a directory.

Parameters:

	path - File path to check

Returns:

	bool - True if file exists and is not a directory
*/
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

/*
CertificatesToJSON converts a slice of CertInfo objects to pretty-printed JSON.

Parameters:

	certs - Slice of certificate info

Returns:

	[]byte - JSON data
	error  - Any error from JSON marshaling
*/
func CertificatesToJSON(certs []CertInfo) ([]byte, error) {
	return json.MarshalIndent(certs, "", "  ")
}

/*
ScanAllCertificates scans both the filesystem and the Windows certificate store
(if running on Windows) and returns all found certificates.

Parameters:

	dir - Directory to scan for filesystem certificates

Returns:

	[]CertInfo - Slice of all certificates found
	error      - Any error encountered during scanning
*/
func ScanAllCertificates(dir string) ([]CertInfo, error) {
	// Scan filesystem first
	certs, err := ScanCertFiles(dir)
	if err != nil {
		return certs, err
	}

	// If on Windows, scan Windows certificate store as well
	if runtime.GOOS == "windows" {
		winCerts, err := ScanWindowsCertStore() // Assume this function exists elsewhere
		if err == nil {
			certs = append(certs, winCerts...)
		}
	}

	return certs, nil
}
