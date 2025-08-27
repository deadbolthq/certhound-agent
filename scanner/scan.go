package scanner

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ScanCertFiles scans a given directory for PEM/CRT certificate files
func ScanCertFiles(dir string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only scan files
		if info.IsDir() {
			return nil
		}

		// Read file content
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil // ignore unreadable files
		}

		// Parse PEM blocks
		for {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					certs = append(certs, cert)
				}
			}
			data = rest
		}
		return nil
	})

	return certs, err
}

// PrintCertInfo prints basic info about each certificate
func PrintCertInfo(certs []*x509.Certificate) {
	for _, cert := range certs {
		fmt.Println("Subject:", cert.Subject)
		fmt.Println("Issuer:", cert.Issuer)
		fmt.Println("NotBefore:", cert.NotBefore)
		fmt.Println("NotAfter:", cert.NotAfter)
		fmt.Println("SANs:", cert.DNSNames)
		fmt.Println("-------------------------")
	}
}
