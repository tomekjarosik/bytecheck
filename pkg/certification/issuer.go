package certification

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
)

// Certificate defines the interface for any certificate structure.
// This decouples verification logic from the concrete cert implementation.
type Certificate interface {
	Name() string

	// PublicKey returns the public key of the certificate's subject.
	PublicKey() ed25519.PublicKey

	// Signature returns the signature from the issuer.
	Signature() []byte

	// IssuerPublicKey returns the public key of the certificate's issuer.
	IssuerPublicKey() ed25519.PublicKey
}

// SimpleCertificate is the concrete implementation of the Certificate interface.
// This struct holds the actual data and handles JSON marshaling directly.
type SimpleCertificate struct {
	CertName     string `json:"name"`
	PubKey       string `json:"publicKey"`       // Hex-encoded
	Sig          string `json:"signature"`       // Hex-encoded
	IssuerPubKey string `json:"issuerPublicKey"` // Hex-encoded
}

// NewSimpleCertificate creates a new certificate struct.
func NewSimpleCertificate(name string, pubKey, issuerPubKey ed25519.PublicKey, sig []byte) *SimpleCertificate {
	return &SimpleCertificate{
		CertName:     name,
		PubKey:       hex.EncodeToString(pubKey),
		Sig:          hex.EncodeToString(sig),
		IssuerPubKey: hex.EncodeToString(issuerPubKey),
	}
}

// Name implements the Certificate interface.
func (c *SimpleCertificate) Name() string {
	return c.CertName
}

// PublicKey implements the Certificate interface.
func (c *SimpleCertificate) PublicKey() ed25519.PublicKey {
	key, _ := hex.DecodeString(c.PubKey)
	return key
}

// Signature implements the Certificate interface.
func (c *SimpleCertificate) Signature() []byte {
	sig, _ := hex.DecodeString(c.Sig)
	return sig
}

// IssuerPublicKey implements the Certificate interface.
func (c *SimpleCertificate) IssuerPublicKey() ed25519.PublicKey {
	key, _ := hex.DecodeString(c.IssuerPubKey)
	return key
}

// IssueCertificate creates a new certificate by signing a subject's public key
// with an issuer's Signer.
func IssueCertificate(name string, subjectPublicKey ed25519.PublicKey, issuer Signer) (Certificate, error) {
	if subjectPublicKey == nil || issuer == nil {
		return nil, errors.New("subject public key and issuer cannot be nil")
	}

	// Sign the public key of the new certificate
	signature, err := issuer.Sign(subjectPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign subject public key: %w", err)
	}

	cert := NewSimpleCertificate(name, subjectPublicKey, issuer.PublicKey(), signature)
	return cert, nil
}

// CreateRootCertificate creates a self-signed root certificate from a Signer.
func CreateRootCertificate(name string, rootSigner Signer) (Certificate, error) {
	if rootSigner == nil {
		return nil, errors.New("root signer cannot be nil")
	}
	// The signer issues a certificate for its own public key
	return IssueCertificate(name, rootSigner.PublicKey(), rootSigner)
}
