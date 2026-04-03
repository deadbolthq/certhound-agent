/*
Package scanner provides utilities for scanning X.509 certificates from the filesystem
and converting them to a JSON-friendly format. It supports Linux, macOS, and Windows
by optionally scanning the Windows certificate store.

Author: Will Keel
Date: 2025-08-27
*/

package scanner

import (
	"crypto/sha256" // For computing certificate fingerprints
	"crypto/x509"   // For parsing X.509 certificates
	"encoding/hex"  // For encoding fingerprints as hex strings
	"encoding/json" // For JSON marshaling
	"encoding/pem"  // For decoding PEM blocks
	"fmt"           // For error formatting
	"io/fs"         // For file system directory walking
	"math/big"      // For handling big integers (serial numbers
	"os"            // For reading files and checking existence
	"path/filepath" // For cross-platform file path handling
	"runtime"       // For detecting operating system
	"strings"       // For string manipulation
	"time"          // For working with certificate expiration dates

	"github.com/deadbolthq/certhound-agent/internal/config" // For accessing configuration (e.g. ExpiringThresholdDays)
	"github.com/deadbolthq/certhound-agent/internal/logger" // For logging
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
	SerialNumber string   `json:"serial_number"`
	Fingerprint  string   `json:"fingerprint_sha256"`
	KeyUsage     []string `json:"key_usage,omitempty"`
	ExtKeyUsage  []string `json:"extended_key_usage,omitempty"`
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
func ScanCertFiles(dir string, cfg *config.Config) ([]CertInfo, error) {
	var certInfos []CertInfo

	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("scan path unavailable %q: %w", dir, err)
	}

	logger.Infof("Scanning filesystem path: %s", filepath.Clean(dir))

	// WalkDir recursively traverses the directory tree
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Log and continue, don't abort the entire walk
			logger.Warnf("Cannot access %s: %v", path, err)
			return nil
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Read the file contents
		data, err := os.ReadFile(path)
		if err != nil {
			// unreadable file — debug-level message
			logger.Debugf("Unreadable file %s: %v", path, err)
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
			if block.Type != "CERTIFICATE" {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// Skip invalid certificates
				logger.Debugf("Failed to parse certificate in %s: %v", path, err)
				continue
			}

			// honor IncludeSelfSigned setting
			if !cfg.IncludeSelfSigned {
				if len(cert.DNSNames) == 0 && !isLikelyDomainCert(cert) {
					logger.Debugf("Skipping non-domain/self-signed cert: %s", cert.Subject.String())
					continue
				}
			}

			// IPs optionally included
			ipStrs := []string{}
			if cfg.IncludeIPAddresses {
				for _, ip := range cert.IPAddresses {
					ipStrs = append(ipStrs, ip.String())
				}
			}

			// Check if the certificate expires within ExpiringThresholdDays
			expiringSoon := time.Until(cert.NotAfter) <= time.Duration(cfg.ExpiringThresholdDays)*24*time.Hour

			// Append a new CertInfo object to the result slice
			certInfos = append(certInfos, CertInfo{
				Subject:      cert.Subject.String(),
				Issuer:       cert.Issuer.String(),
				SerialNumber: getSerialHex(cert.SerialNumber),
				Fingerprint:  getFingerprintSHA256(cert),
				KeyUsage:     mapKeyUsage(cert.KeyUsage),
				ExtKeyUsage:  mapExtKeyUsage(cert.ExtKeyUsage),
				NotBefore:    cert.NotBefore.Format(time.RFC3339),
				NotAfter:     cert.NotAfter.Format(time.RFC3339),
				DNSNames:     cert.DNSNames,
				IPAddresses:  ipStrs,
				CertPath:     path,
				KeyPath:      guessKeyPath(path),
				ExpiringSoon: expiringSoon,
			})

		}

		return nil
	})

	if err != nil {
		logger.Errorf("Error walking directory %s: %v", dir, err)
	}

	logger.Infof("Completed scan of %s, found %d filesystem certs", dir, len(certInfos))
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
	linuxPath := filepath.Join("/etc", "ssl", "private", baseName)
	if fileExists(linuxPath) {
		return linuxPath
	}

	// Windows default private key directory
	winPath := filepath.Join("C:", "ProgramData", "SSL", "Keys", baseName)
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
func ScanAllCertificates(dir string, cfg *config.Config) ([]CertInfo, error) {
	// Scan filesystem first
	certs, err := ScanCertFiles(dir, cfg)
	if err != nil {
		return certs, err
	}

	// If on Windows, scan Windows certificate stores as well
	if runtime.GOOS == "windows" {
		winCerts, err := ScanWindowsCertStore(cfg)
		if err != nil {
			// log but don't fail the overall operation
			logger.Warnf("Windows cert store scan error: %v", err)
		} else {
			certs = append(certs, winCerts...)
		}
	}

	return certs, nil
}

// getFingerprintSHA256 computes the SHA-256 fingerprint of a certificate.
func getFingerprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// getSerialHex returns the serial number of a certificate as a hexadecimal string.
func getSerialHex(sn *big.Int) string {
	if sn == nil {
		return ""
	}
	return strings.ToUpper(sn.Text(16))
}

// mapKeyUsage converts the KeyUsage bitmask to a slice of human-readable strings.
func mapKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

// mapExtKeyUsage converts the ExtendedKeyUsage slice to a slice of human-readable strings.
func mapExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	var usages []string
	for _, usage := range eku {
		switch usage {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "NetscapeServerGatedCrypto")
		default:
			usages = append(usages, "Unknown")
		}
	}
	return usages
}
