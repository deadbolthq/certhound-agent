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

	"github.com/keelw/certsync-agent/internal/config" // For accessing configuration settings
	"github.com/keelw/certsync-agent/internal/logger" // For logging
	"golang.org/x/sys/windows"                        // Windows API bindings for certificate store access
)

// WindowsKeyPath is a placeholder string for private key locations.
// Windows certificate stores do not expose filesystem paths for private keys.
// This constant will always be returned in KeyPath for Windows certificates.
const WindowsKeyPath = "WINDOWS_STORE_KEY"

// ScanWindowsCertStore scans multiple Windows certificate stores and returns
// certificates in CertInfo format.
func ScanWindowsCertStore(cfg *config.Config) ([]CertInfo, error) {
	var certInfos []CertInfo

	var windowsStores = []struct {
		systemStore uint32
		storeName   string
	}{
		{windows.CERT_SYSTEM_STORE_CURRENT_USER, "MY"},
		{windows.CERT_SYSTEM_STORE_CURRENT_USER, "ROOT"},
		{windows.CERT_SYSTEM_STORE_CURRENT_USER, "CA"},
		{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, "MY"},
		{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, "ROOT"},
		{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, "CA"},
		{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, "TrustedPeople"},
		{windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, "TrustedPublisher"},
	}

	for _, ws := range windowsStores {
		logger.Infof("Scanning Windows cert store: %s", ws.storeName)

		h, err := windows.CertOpenStore(
			windows.CERT_STORE_PROV_SYSTEM, 0, 0,
			windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG|ws.systemStore,
			uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(ws.storeName))),
		)
		if err != nil {
			logger.Warnf("Could not open Windows cert store %s: %v", ws.storeName, err)
			continue
		}

		var pCertContext *windows.CertContext
		for {
			pCertContext, err = windows.CertEnumCertificatesInStore(h, pCertContext)
			if pCertContext == nil {
				break
			}

			certBytes := (*[1 << 20]byte)(unsafe.Pointer(pCertContext.EncodedCert))[:pCertContext.Length:pCertContext.Length]

			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				logger.Debugf("Skipping invalid cert in %s: %v", ws.storeName, err)
				continue
			}
			if !cfg.IncludeSelfSigned {
				if len(cert.DNSNames) == 0 && !isLikelyDomainCert(cert) {
					logger.Debugf("Skipping non-domain/self-signed cert in %s: %s", ws.storeName, cert.Subject.String())
					continue
				}
			}
			if !isLikelyDomainCert(cert) {
				continue
			}

			var ipStrs []string
			if cfg.IncludeIPAddresses {
				for _, ip := range cert.IPAddresses {
					ipStrs = append(ipStrs, ip.String())
				}
			}

			expiringSoon := time.Until(cert.NotAfter) <= time.Duration(cfg.ExpiringThresholdDays)*24*time.Hour

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
				CertPath:     "WINDOWS_STORE:" + ws.storeName, // ✅ accurate store name
				KeyPath:      WindowsKeyPath,
				ExpiringSoon: expiringSoon,
			})
		}

		if errClose := windows.CertCloseStore(h, 0); errClose != nil {
			logger.Warnf("Failed to close store %s: %v", ws.storeName, errClose)
		}

		logger.Infof("Completed Windows store scan; total certs found: %d", len(certInfos))
	}

	return certInfos, nil
}
