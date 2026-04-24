//go:build windows

package renewal

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ImportPFXToStore persists a renewed cert+key into a Windows certificate
// store (e.g. "LocalMachine\\MY"). It removes any prior certificate whose
// subject CN or SAN matches one of the renewed domains, so repeated
// renewals don't pile up stale certs that IIS or other consumers might
// still pick.
//
// certBundlePEM is the lego output: leaf + intermediate chain, PEM-encoded.
// key is the private key matching the leaf.
func ImportPFXToStore(storeSpec string, certBundlePEM []byte, key interface{}, domains []string) error {
	loc, storeName, err := parseStoreSpec(storeSpec)
	if err != nil {
		return err
	}

	leaf, chain, err := splitCertBundle(certBundlePEM)
	if err != nil {
		return fmt.Errorf("parsing cert bundle: %w", err)
	}

	// Random password — the PFX lives in-memory only, we use it purely as
	// the CryptoAPI hand-off format. 32 hex chars is plenty.
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return fmt.Errorf("generating pfx password: %w", err)
	}
	password := hex.EncodeToString(pwBytes)

	pfxBlob, err := pkcs12.Modern.Encode(key, leaf, chain, password)
	if err != nil {
		return fmt.Errorf("encoding pfx: %w", err)
	}

	// PFXImportCertStore persists the private key into the user or machine
	// keyset depending on flags, then returns a temp memory store holding
	// the cert contexts that reference that key.
	keysetFlag := uint32(windows.CRYPT_USER_KEYSET)
	if loc == windows.CERT_SYSTEM_STORE_LOCAL_MACHINE {
		keysetFlag = windows.CRYPT_MACHINE_KEYSET
	}
	importFlags := keysetFlag | windows.CRYPT_EXPORTABLE

	pwUTF16, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return fmt.Errorf("pfx password conv: %w", err)
	}
	blob := windows.CryptDataBlob{
		Size: uint32(len(pfxBlob)),
		Data: &pfxBlob[0],
	}
	tempStore, err := windows.PFXImportCertStore(&blob, pwUTF16, importFlags)
	if err != nil {
		return fmt.Errorf("PFXImportCertStore: %w", err)
	}
	defer windows.CertCloseStore(tempStore, 0)

	// Open the destination system store with write access.
	storeNameUTF16, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return fmt.Errorf("store name conv: %w", err)
	}
	destStore, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_STORE_OPEN_EXISTING_FLAG|loc,
		uintptr(unsafe.Pointer(storeNameUTF16)),
	)
	if err != nil {
		return fmt.Errorf("opening dest store %s: %w", storeSpec, err)
	}
	defer windows.CertCloseStore(destStore, 0)

	// Remove any existing certs matching our domains so repeat renewals
	// don't accumulate stale contexts that consumers might still pick by
	// subject instead of by thumbprint.
	if removed, err := deleteCertsMatchingDomains(destStore, domains); err != nil {
		return fmt.Errorf("removing stale certs: %w", err)
	} else if removed > 0 {
		// caller-side logging handles this
	}

	// Walk each cert in the temp store and copy it into the destination.
	// We only copy the leaf (the one whose subject CN/SAN matches one of
	// our domains) — intermediates belong in CA stores, not MY, and
	// trusted roots are already installed system-wide.
	var pCtx *windows.CertContext
	for {
		pCtx, err = windows.CertEnumCertificatesInStore(tempStore, pCtx)
		if pCtx == nil {
			break
		}
		cert, perr := parseCertFromContext(pCtx)
		if perr != nil {
			continue
		}
		if !certMatchesAnyDomain(cert, domains) {
			continue
		}
		if err := windows.CertAddCertificateContextToStore(
			destStore, pCtx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil,
		); err != nil {
			return fmt.Errorf("adding cert to %s: %w", storeSpec, err)
		}
	}

	return nil
}

// parseStoreSpec splits "LocalMachine\MY" into a CERT_SYSTEM_STORE_* flag
// and the store name. The separator is a literal backslash in JSON config,
// which in Go source looks like "LocalMachine\\MY".
func parseStoreSpec(spec string) (uint32, string, error) {
	parts := strings.SplitN(spec, `\`, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, "", fmt.Errorf("invalid WindowsCertStore %q (expected Location\\Name, e.g. LocalMachine\\MY)", spec)
	}
	switch strings.ToLower(parts[0]) {
	case "localmachine":
		return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, parts[1], nil
	case "currentuser":
		return windows.CERT_SYSTEM_STORE_CURRENT_USER, parts[1], nil
	default:
		return 0, "", fmt.Errorf("invalid store location %q (use LocalMachine or CurrentUser)", parts[0])
	}
}

// splitCertBundle returns (leaf, chain) from a PEM bundle as emitted by lego.
// The first CERTIFICATE block is treated as the leaf; the rest are intermediates.
func splitCertBundle(pemBundle []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var leaf *x509.Certificate
	var chain []*x509.Certificate
	rest := pemBundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		if leaf == nil {
			leaf = cert
		} else {
			chain = append(chain, cert)
		}
	}
	if leaf == nil {
		return nil, nil, fmt.Errorf("no CERTIFICATE blocks in bundle")
	}
	return leaf, chain, nil
}

// parseCertFromContext extracts the encoded cert bytes from a CertContext
// and parses them as an x509.Certificate.
func parseCertFromContext(ctx *windows.CertContext) (*x509.Certificate, error) {
	if ctx == nil || ctx.EncodedCert == nil || ctx.Length == 0 {
		return nil, fmt.Errorf("empty cert context")
	}
	// EncodedCert points into the CryptoAPI-owned buffer; copy before parsing
	// so we don't hold a pointer into memory we don't control after the
	// enumeration advances.
	raw := make([]byte, ctx.Length)
	copy(raw, (*[1 << 20]byte)(unsafe.Pointer(ctx.EncodedCert))[:ctx.Length:ctx.Length])
	return x509.ParseCertificate(raw)
}

// certMatchesAnyDomain returns true if the cert's subject CN or any DNS SAN
// matches one of the domains (case-insensitive).
func certMatchesAnyDomain(cert *x509.Certificate, domains []string) bool {
	names := append([]string{}, cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		names = append(names, cert.Subject.CommonName)
	}
	for _, d := range domains {
		for _, n := range names {
			if strings.EqualFold(d, n) {
				return true
			}
		}
	}
	return false
}

// deleteCertsMatchingDomains enumerates the store and deletes every cert
// whose CN or SAN matches one of the given domains. Returns the number of
// certs removed. Callers must be sure the new cert is not yet in the store.
func deleteCertsMatchingDomains(store windows.Handle, domains []string) (int, error) {
	var removed int
	var pCtx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, pCtx)
		if next == nil {
			// End of enumeration. CertEnumCertificatesInStore returns
			// CRYPT_E_NOT_FOUND at the end; treat that as clean termination.
			_ = err
			break
		}
		cert, perr := parseCertFromContext(next)
		if perr != nil {
			pCtx = next
			continue
		}
		if !certMatchesAnyDomain(cert, domains) {
			pCtx = next
			continue
		}
		// Duplicate the context — CertDeleteCertificateFromStore frees the
		// one it's given, which would break the enumeration cursor.
		dup := windows.CertDuplicateCertificateContext(next)
		if dup == nil {
			pCtx = next
			continue
		}
		pCtx = next // advance enumeration past the one we're about to delete
		if err := windows.CertDeleteCertificateFromStore(dup); err != nil {
			return removed, fmt.Errorf("deleting stale cert: %w", err)
		}
		removed++
	}
	return removed, nil
}
