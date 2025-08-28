//go:build windows
// +build windows

/*
Package scanner provides utilities for scanning X.509 certificates.

This file contains Windows-specific functionality to scan certificates from the
current user's Windows certificate store ("MY" store).

Author: Will Keel
Date: 2025-08-27
*/

package scanner

import (
	"crypto/x509" // For parsing X.509 certificates
	"time"        // For working with certificate expiration dates
	"unsafe"      // For converting pointers to byte slices

	"golang.org/x/sys/windows" // Windows API bindings for certificate store access
)

/*
ScanWindowsCertStore scans the current user's "MY" certificate store on Windows
and returns certificates in JSON-friendly CertInfo format.

Behavior:
1. Opens the "MY" system certificate store in read-only mode.
2. Enumerates all certificates in the store.
3. Parses each certificate and filters out non-domain/self-signed root certificates.
4. Converts IP addresses to strings and checks if the certificate is expiring soon.
5. Returns a slice of CertInfo objects representing all valid domain certificates.

Returns:

	[]CertInfo - Slice of certificates
	error      - Any error encountered while opening or reading the store
*/
func ScanWindowsCertStore() ([]CertInfo, error) {
	var certInfos []CertInfo

	// Open the current user's "MY" certificate store in read-only mode
	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG|windows.CERT_SYSTEM_STORE_CURRENT_USER,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("MY"))),
	)
	if err != nil {
		return nil, err
	}
	// Ensure the store handle is closed at the end
	defer windows.CertCloseStore(h, 0)

	var pCertContext *windows.CertContext
	for {
		// Enumerate certificates; pass previous context to get next
		pCertContext, err = windows.CertEnumCertificatesInStore(h, pCertContext)
		if pCertContext == nil {
			// No more certificates in the store
			break
		}

		// Convert encoded certificate bytes to Go slice
		certBytes := (*[1 << 20]byte)(unsafe.Pointer(pCertContext.EncodedCert))[:pCertContext.Length:pCertContext.Length]

		// Parse the X.509 certificate
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			// Skip invalid certificates
			continue
		}

		// Skip self-signed root CAs
		if !isLikelyDomainCert(cert) {
			continue
		}

		// Convert IP addresses to string format
		ipStrs := []string{}
		for _, ip := range cert.IPAddresses {
			ipStrs = append(ipStrs, ip.String())
		}

		// Determine if certificate expires within 30 days
		expiringSoon := time.Until(cert.NotAfter) < 30*24*time.Hour

		// Append certificate information to the result slice
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
			CertPath:     "WINDOWS_STORE:MY",  // Indicates source is Windows store
			KeyPath:      "WINDOWS_STORE_KEY", // Placeholder; actual private key handling may differ
			ExpiringSoon: expiringSoon,
		})
	}

	return certInfos, nil
}
