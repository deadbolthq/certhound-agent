package scanner

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CertInfo is a JSON-friendly representation of a certificate
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

// ScanCertFiles scans a directory for PEM/CRT certificate files
func ScanCertFiles(dir string) ([]CertInfo, error) {
	var certInfos []CertInfo

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}

			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}

				if len(cert.DNSNames) == 0 && !isLikelyDomainCert(cert) {
					continue
				}

				ipStrs := []string{}
				for _, ip := range cert.IPAddresses {
					ipStrs = append(ipStrs, ip.String())
				}

				expiringSoon := time.Until(cert.NotAfter) < 30*24*time.Hour

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

// isLikelyDomainCert skips self-signed root CAs
func isLikelyDomainCert(cert *x509.Certificate) bool {
	return cert.Issuer.String() != cert.Subject.String()
}

// guessKeyPath guesses the private key path for a given certificate
func guessKeyPath(certPath string) string {
	base := filepath.Base(certPath)
	ext := filepath.Ext(base)
	baseName := strings.TrimSuffix(base, ext) + ".key"

	// Linux default
	linuxPath := filepath.Join("/etc/ssl/private", baseName)
	if fileExists(linuxPath) {
		return linuxPath
	}

	// Windows default
	winPath := filepath.Join("C:\\ProgramData\\SSL\\Keys", baseName)
	if fileExists(winPath) {
		return winPath
	}

	return ""
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// CertificatesToJSON converts CertInfo slice to pretty JSON
func CertificatesToJSON(certs []CertInfo) ([]byte, error) {
	return json.MarshalIndent(certs, "", "  ")
}

// ScanAllCertificates scans filesystem and Windows store (if on Windows)
func ScanAllCertificates(dir string) ([]CertInfo, error) {
	certs, err := ScanCertFiles(dir)
	if err != nil {
		return certs, err
	}

	if runtime.GOOS == "windows" {
		winCerts, err := ScanWindowsCertStore()
		if err == nil {
			certs = append(certs, winCerts...)
		}
	}

	return certs, nil
}
