package scanner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
)

// generateCert creates a self-signed certificate and returns its PEM bytes.
// If dnsNames is non-empty the cert will pass the domain-cert filter.
func generateCert(t *testing.T, subject pkix.Name, dnsNames []string, notAfter time.Time) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func defaultCfg() *config.Config {
	return &config.Config{
		ExpiringThresholdDays: 30,
		IncludeSelfSigned:     false,
		IncludeIPAddresses:    false,
	}
}

// ---- isLikelyDomainCert ----

func TestIsLikelyDomainCert_SelfSigned(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "root"},
		Issuer:  pkix.Name{CommonName: "root"},
	}
	if isLikelyDomainCert(cert) {
		t.Error("self-signed cert should not be considered a domain cert")
	}
}

func TestIsLikelyDomainCert_Issued(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "example.com"},
		Issuer:  pkix.Name{CommonName: "Let's Encrypt"},
	}
	if !isLikelyDomainCert(cert) {
		t.Error("CA-issued cert should be considered a domain cert")
	}
}

// ---- getFingerprintSHA256 ----

func TestGetFingerprintSHA256_Deterministic(t *testing.T) {
	pemBytes := generateCert(t, pkix.Name{CommonName: "test.example.com"}, []string{"test.example.com"}, time.Now().Add(90*24*time.Hour))
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fp1 := getFingerprintSHA256(cert)
	fp2 := getFingerprintSHA256(cert)
	if fp1 != fp2 {
		t.Error("fingerprint should be deterministic")
	}
	if len(fp1) != 64 {
		t.Errorf("SHA-256 hex fingerprint should be 64 chars, got %d", len(fp1))
	}
}

// ---- getSerialHex ----

func TestGetSerialHex(t *testing.T) {
	cases := []struct {
		n    *big.Int
		want string
	}{
		{nil, ""},
		{big.NewInt(0), "0"},
		{big.NewInt(255), "FF"},
		{big.NewInt(256), "100"},
	}
	for _, tc := range cases {
		got := getSerialHex(tc.n)
		if got != tc.want {
			t.Errorf("getSerialHex(%v) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// ---- mapKeyUsage ----

func TestMapKeyUsage_DigitalSignature(t *testing.T) {
	usages := mapKeyUsage(x509.KeyUsageDigitalSignature)
	if len(usages) != 1 || usages[0] != "DigitalSignature" {
		t.Errorf("unexpected usages: %v", usages)
	}
}

func TestMapKeyUsage_Multiple(t *testing.T) {
	ku := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	usages := mapKeyUsage(ku)
	if len(usages) != 2 {
		t.Errorf("expected 2 usages, got %d: %v", len(usages), usages)
	}
}

func TestMapKeyUsage_Zero(t *testing.T) {
	usages := mapKeyUsage(0)
	if len(usages) != 0 {
		t.Errorf("expected no usages for zero bitmask, got %v", usages)
	}
}

// ---- mapExtKeyUsage ----

func TestMapExtKeyUsage(t *testing.T) {
	ekus := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	usages := mapExtKeyUsage(ekus)
	if len(usages) != 2 {
		t.Fatalf("expected 2 ext usages, got %d", len(usages))
	}
	if usages[0] != "ServerAuth" || usages[1] != "ClientAuth" {
		t.Errorf("unexpected ext usages: %v", usages)
	}
}

func TestMapExtKeyUsage_Empty(t *testing.T) {
	if usages := mapExtKeyUsage(nil); len(usages) != 0 {
		t.Errorf("expected empty slice, got %v", usages)
	}
}

// ---- ScanCertFiles ----

func writePEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanCertFiles_FindsDomainCert(t *testing.T) {
	dir := t.TempDir()
	pemBytes := generateCert(t, pkix.Name{CommonName: "example.com"}, []string{"example.com"}, time.Now().Add(90*24*time.Hour))
	writePEM(t, dir, "example.pem", pemBytes)

	certs, err := ScanCertFiles(dir, defaultCfg())
	if err != nil {
		t.Fatalf("ScanCertFiles: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].DNSNames[0] != "example.com" {
		t.Errorf("unexpected DNSName: %v", certs[0].DNSNames)
	}
}

func TestScanCertFiles_SkipsSelfSignedByDefault(t *testing.T) {
	dir := t.TempDir()
	// Self-signed with no DNS names — should be filtered
	pemBytes := generateCert(t, pkix.Name{CommonName: "internal-ca"}, nil, time.Now().Add(365*24*time.Hour))
	writePEM(t, dir, "ca.pem", pemBytes)

	certs, err := ScanCertFiles(dir, defaultCfg())
	if err != nil {
		t.Fatalf("ScanCertFiles: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs (self-signed filtered), got %d", len(certs))
	}
}

func TestScanCertFiles_IncludeSelfSigned(t *testing.T) {
	dir := t.TempDir()
	pemBytes := generateCert(t, pkix.Name{CommonName: "internal-ca"}, nil, time.Now().Add(365*24*time.Hour))
	writePEM(t, dir, "ca.pem", pemBytes)

	cfg := defaultCfg()
	cfg.IncludeSelfSigned = true
	certs, err := ScanCertFiles(dir, cfg)
	if err != nil {
		t.Fatalf("ScanCertFiles: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 cert with IncludeSelfSigned=true, got %d", len(certs))
	}
}

func TestScanCertFiles_ExpiringSoon(t *testing.T) {
	dir := t.TempDir()
	// Expires in 5 days — within default 30-day threshold
	pemBytes := generateCert(t, pkix.Name{CommonName: "soon.example.com"}, []string{"soon.example.com"}, time.Now().Add(5*24*time.Hour))
	writePEM(t, dir, "soon.pem", pemBytes)

	certs, err := ScanCertFiles(dir, defaultCfg())
	if err != nil {
		t.Fatalf("ScanCertFiles: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if !certs[0].ExpiringSoon {
		t.Error("cert expiring in 5 days should have ExpiringSoon=true")
	}
}

func TestScanCertFiles_IgnoresNonPEM(t *testing.T) {
	dir := t.TempDir()
	writePEM(t, dir, "notacert.txt", []byte("just some text, not a cert"))

	certs, err := ScanCertFiles(dir, defaultCfg())
	if err != nil {
		t.Fatalf("ScanCertFiles: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs from non-PEM file, got %d", len(certs))
	}
}

func TestScanCertFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	certs, err := ScanCertFiles(dir, defaultCfg())
	if err != nil {
		t.Fatalf("ScanCertFiles: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs in empty dir, got %d", len(certs))
	}
}

func TestScanCertFiles_NonexistentDir(t *testing.T) {
	_, err := ScanCertFiles("/nonexistent/path/that/does/not/exist", defaultCfg())
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestScanCertFiles_ExpiredCert(t *testing.T) {
	dir := t.TempDir()
	pemBytes := generateCert(t, pkix.Name{CommonName: "expired.example.com"}, []string{"expired.example.com"}, time.Now().Add(-24*time.Hour))
	writePEM(t, dir, "expired.pem", pemBytes)

	cfg := defaultCfg()
	cfg.IncludeSelfSigned = true
	certs, err := ScanCertFiles(dir, cfg)
	if err != nil {
		t.Fatalf("ScanCertFiles: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if !certs[0].Expired {
		t.Error("cert with NotAfter in the past should have Expired=true")
	}
}

func TestScanCertFiles_FingerprintPresent(t *testing.T) {
	dir := t.TempDir()
	pemBytes := generateCert(t, pkix.Name{CommonName: "fp.example.com"}, []string{"fp.example.com"}, time.Now().Add(90*24*time.Hour))
	writePEM(t, dir, "fp.pem", pemBytes)

	certs, _ := ScanCertFiles(dir, defaultCfg())
	if len(certs) == 0 {
		t.Fatal("expected 1 cert")
	}
	if len(certs[0].Fingerprint) != 64 {
		t.Errorf("fingerprint should be 64-char hex, got %q", certs[0].Fingerprint)
	}
}
