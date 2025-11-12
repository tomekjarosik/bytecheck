package certification

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

var ErrNotImplemented = errors.New("not implemented")

type Signer interface {
	Sign(data []byte) ([]byte, error)
	PublicKey() ed25519.PublicKey
	Close() error
}

var _ Signer = (*Ed25519Signer)(nil)

// Ed25519Signer is an implementation of the Signer interface
// that holds a private key in memory.
type Ed25519Signer struct {
	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

// NewEd25519Signer generates a new key pair and returns a
// Signer implementation.
func NewEd25519Signer(pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{
		privKey: privKey,
		pubKey:  pubKey,
	}
}

// NewEd25519SignerFromFile reads an SSH-formatted ed25519 private key from a file
// and returns a new Signer. It will prompt for a passphrase if the key is encrypted.
func NewEd25519SignerFromFile(filePath string) (*Ed25519Signer, error) {
	reader := NewEd25519KeyReader()

	privateKey, err := reader.ReadKeyFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read SSH private key from file: %w", err)
	}

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to derive public key from private key")
	}

	// 4. Create the signer using the loaded keys
	return &Ed25519Signer{
		privKey: privateKey,
		pubKey:  publicKey,
	}, nil
}

// Sign implements the Signer interface.
func (s *Ed25519Signer) Sign(data []byte) ([]byte, error) {
	// ed25519.Sign doesn't return an error, but we return nil
	// to satisfy the interface, which anticipates errors from
	// other implementations (like a YubiKey I/O error).
	signature := ed25519.Sign(s.privKey, data)
	return signature, nil
}

func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.pubKey
}

func (s *Ed25519Signer) Close() error {
	return nil
}

type FakeSigner struct{}

func NewFakeSigner() *FakeSigner {
	return &FakeSigner{}
}

func (s *FakeSigner) Sign(data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

func (s *FakeSigner) PublicKey() ed25519.PublicKey {
	return []byte("fake-public-key")
}

func (s *FakeSigner) Close() error {
	return nil
}
