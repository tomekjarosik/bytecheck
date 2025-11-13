package certification

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Certificate defines the interface for any certificate structure.
// This decouples verification logic from the concrete cert implementation.
type Certificate interface {

	// PublicKey returns the public key of the certificate's subject.
	PublicKey() ed25519.PublicKey

	// Signature returns the signature from the issuer.
	Signature() []byte

	// IssuerPublicKey returns the public key of the certificate's issuer.
	IssuerPublicKey() ed25519.PublicKey

	// IssuerReference return a string describing an issuer which can be validated externally (e.g. github keys)
	IssuerReference() string

	Verify() bool
}

// SimpleCertificate is the concrete implementation of the Certificate interface.
// This struct holds the actual data and handles JSON marshaling directly.
type SimpleCertificate struct {
	PubKey       ed25519.PublicKey `json:"-"`
	Sig          []byte            `json:"-"`
	IssuerPubKey ed25519.PublicKey `json:"-"`
	IssuerRef    string            `json:"-"`
}

// NewSimpleCertificate creates a new certificate struct.
func NewSimpleCertificate(pubKey, issuerPubKey ed25519.PublicKey, issuerRef string, sig []byte) *SimpleCertificate {
	return &SimpleCertificate{
		PubKey:       pubKey,
		Sig:          sig,
		IssuerPubKey: issuerPubKey,
		IssuerRef:    issuerRef,
	}
}

// IssuerReference implements the Certificate interface
func (c *SimpleCertificate) IssuerReference() string {
	return c.IssuerRef
}

// PublicKey implements the Certificate interface.
func (c *SimpleCertificate) PublicKey() ed25519.PublicKey {
	return c.PubKey
}

// Signature implements the Certificate interface.
func (c *SimpleCertificate) Signature() []byte {
	return c.Sig
}

// IssuerPublicKey implements the Certificate interface.
func (c *SimpleCertificate) IssuerPublicKey() ed25519.PublicKey {
	return c.IssuerPubKey
}

// dataToSign concatenates the public key and reference to create a consistent payload for signing and verification.
func (c *SimpleCertificate) dataToSign() []byte {
	return append(c.PubKey[:], []byte(c.IssuerRef)...)
}

// IssueCertificate creates a new certificate by signing a subject's public key
// with an issuer's Signer.
func IssueCertificate(subjectPublicKey ed25519.PublicKey, issuer Signer, issuerReference string) (*SimpleCertificate, error) {
	if subjectPublicKey == nil || issuer == nil {
		return nil, errors.New("subject public key and issuer cannot be nil")
	}

	cert := &SimpleCertificate{
		PubKey:       subjectPublicKey,
		IssuerRef:    issuerReference,
		IssuerPubKey: issuer.PublicKey(),
	}

	// Sign the public key of the new certificate
	signature, err := issuer.Sign(cert.dataToSign())
	if err != nil {
		return nil, fmt.Errorf("failed to sign subject public key: %w", err)
	}

	cert.Sig = signature
	return cert, nil
}
