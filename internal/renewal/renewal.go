// Package renewal performs ACME certificate renewals using the Let's
// Encrypt HTTP-01 webroot challenge. It writes renewed cert+key pairs to
// disk atomically and runs an optional post-renewal command.
//
// Only HTTP-01 via webroot is supported today. Wildcard certs (which
// require DNS-01) are deliberately out of scope.
package renewal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/deadbolthq/certhound-agent/internal/config"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	legoconf "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"
)

// Result describes the outcome of a renewal attempt for a single RenewalEntry.
type Result struct {
	Domain     string    // primary domain (first in Domains slice)
	Domains    []string  // all domains on the cert
	Success    bool
	Error      string
	NotAfter   time.Time
	FinishedAt time.Time
}

// Client wires a lego ACME client with a persistent account key and a
// webroot HTTP-01 provider. One Client instance is reused across renewals
// so we don't re-register the ACME account every time.
type Client struct {
	cfg    config.Renewal
	lego   *legoconf.Client
	user   *acmeUser
}

// NewClient registers (or re-uses) an ACME account and returns a ready-to-use
// Client. Safe to call every time the agent starts.
func NewClient(cfg config.Renewal) (*Client, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("renewal is not enabled in config")
	}
	if cfg.ACMEEmail == "" {
		return nil, fmt.Errorf("renewal.ACMEEmail is required")
	}

	accountKey, err := loadOrCreateAccountKey(cfg.AccountKeyPath)
	if err != nil {
		return nil, err
	}

	user := &acmeUser{
		email: cfg.ACMEEmail,
		key:   accountKey,
	}

	legoCfg := legoconf.NewConfig(user)
	if cfg.ACMEDirectoryURL != "" {
		legoCfg.CADirURL = cfg.ACMEDirectoryURL
	}
	legoCfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := legoconf.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("creating lego client: %w", err)
	}

	// Register the account on first use. If already registered with Let's
	// Encrypt for this key, this is a no-op that returns the existing reg.
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering ACME account: %w", err)
	}
	user.registration = reg

	return &Client{cfg: cfg, lego: client, user: user}, nil
}

// Renew obtains a fresh certificate for the given entry using the HTTP-01
// webroot challenge, writes it to disk, and runs the post-renewal command
// if configured. Returns a Result describing the outcome.
func (c *Client) Renew(entry config.RenewalEntry) Result {
	primary := ""
	if len(entry.Domains) > 0 {
		primary = entry.Domains[0]
	}
	result := Result{
		Domain:     primary,
		Domains:    entry.Domains,
		FinishedAt: time.Now().UTC(),
	}

	provider, err := webroot.NewHTTPProvider(entry.WebrootPath)
	if err != nil {
		result.Error = fmt.Sprintf("webroot provider: %v", err)
		return result
	}
	if err := c.lego.Challenge.SetHTTP01Provider(provider); err != nil {
		result.Error = fmt.Sprintf("setting challenge provider: %v", err)
		return result
	}

	// Generate a fresh cert private key. Never reuse the old one — a renewed
	// cert should be a completely new keypair.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		result.Error = fmt.Sprintf("generating cert key: %v", err)
		return result
	}

	req := certificate.ObtainRequest{
		Domains:    entry.Domains,
		Bundle:     true,
		PrivateKey: certKey,
	}
	certs, err := c.lego.Certificate.Obtain(req)
	if err != nil {
		result.Error = fmt.Sprintf("obtaining certificate: %v", err)
		result.FinishedAt = time.Now().UTC()
		return result
	}

	// Parse NotAfter so we can report the new expiry.
	if parsed, perr := parseLeafCert(certs.Certificate); perr == nil {
		result.NotAfter = parsed.NotAfter
	}

	// Write the new key (from our generated certKey, not certs.PrivateKey,
	// because lego returns certs.PrivateKey only when it generated the key
	// itself — here we passed one in).
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		result.Error = fmt.Sprintf("marshaling cert key: %v", err)
		return result
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeAtomic(entry.KeyOutputPath, keyPEM, 0600); err != nil {
		result.Error = fmt.Sprintf("writing key: %v", err)
		return result
	}
	if err := writeAtomic(entry.CertOutputPath, certs.Certificate, 0644); err != nil {
		result.Error = fmt.Sprintf("writing cert: %v", err)
		return result
	}

	// Post-renewal reload command — best-effort. If it fails, we still
	// consider the renewal successful (the cert is on disk) but surface
	// the error in the result message so the user sees it in the dashboard.
	if entry.PostRenewalCommand != "" {
		if out, err := runPostCommand(entry.PostRenewalCommand); err != nil {
			result.Success = true
			result.Error = fmt.Sprintf("cert renewed but post-renewal command failed: %v (%s)", err, string(out))
			result.FinishedAt = time.Now().UTC()
			return result
		}
	}

	result.Success = true
	result.FinishedAt = time.Now().UTC()
	return result
}

// parseLeafCert returns the first certificate from a PEM bundle — this is
// the leaf cert that tells us NotAfter.
func parseLeafCert(pemBundle []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(pemBundle)
		if block == nil {
			return nil, fmt.Errorf("no certificate block in bundle")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		pemBundle = rest
	}
}

// writeAtomic writes data to path via a temp file + rename so readers never
// see a partial file. The temp file is created in the same directory to
// guarantee the rename is atomic (same filesystem).
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	// Clean up tmp on any failure path.
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	tmpPath = "" // success — suppress the deferred cleanup
	return nil
}

// runPostCommand runs a shell command string using the OS's default shell.
// On Windows we use cmd /C, elsewhere /bin/sh -c. This matches how certbot
// and most renewal tools handle --deploy-hook.
func runPostCommand(cmdStr string) ([]byte, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmdStr)
	} else {
		cmd = exec.Command("/bin/sh", "-c", cmdStr)
	}
	return cmd.CombinedOutput()
}
