//go:build windows
// +build windows

package scanner

import (
	"crypto/x509"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ScanWindowsCertStore() ([]CertInfo, error) {
	var certInfos []CertInfo

	h, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG|windows.CERT_SYSTEM_STORE_CURRENT_USER,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("MY"))))
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(h, 0)

	var pCertContext *windows.CertContext
	for {
		pCertContext, err = windows.CertEnumCertificatesInStore(h, pCertContext)
		if pCertContext == nil {
			break
		}

		certBytes := (*[1 << 20]byte)(unsafe.Pointer(pCertContext.EncodedCert))[:pCertContext.Length:pCertContext.Length]
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		if !isLikelyDomainCert(cert) {
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
			CertPath:     "WINDOWS_STORE:MY",
			KeyPath:      "WINDOWS_STORE_KEY", // placeholder
			ExpiringSoon: expiringSoon,
		})
	}

	return certInfos, nil
}
