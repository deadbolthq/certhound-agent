package renewal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/registration"
)

// acmeUser implements lego's registration.User interface. Backed by a
// persistent ECDSA key on disk so repeat renewals reuse the same ACME account.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// loadOrCreateAccountKey loads an existing ECDSA P-256 key from path, or
// generates a new one and writes it atomically if the file doesn't exist.
func loadOrCreateAccountKey(path string) (crypto.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("account key at %s is not valid PEM", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ACME account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling ACME account key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("creating account key dir: %w", err)
	}
	if err := writeAtomic(path, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("writing ACME account key: %w", err)
	}
	return key, nil
}
