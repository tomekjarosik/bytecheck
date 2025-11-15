package generator

import (
	"crypto/ed25519"
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/signing"
	"path/filepath"
)

type Signer interface {
	Sign(data []byte) ([]byte, error)
	Algorithm() string
	PublicKey() (ed25519.PublicKey, error)
	Reference() string
	Close() error
}

type ManifestProcessor interface {
	Process(dirPath string, m *manifest.Manifest, manifestName string) error
}

// SignedProcessor handles manifests with cryptographic signatures
type SignedProcessor struct {
	signerCertificate  manifest.Certificate
	signer             Signer
	manifestsGenerated *[]string
}

// UnsignedProcessor handles manifests without signatures
type UnsignedProcessor struct {
	manifestsGenerated *[]string
}

// NewSignedProcessor creates a processor that signs manifests
func NewSignedProcessor(rootSigner Signer, manifestsGenerated *[]string) (*SignedProcessor, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral signing key: %w", err)
	}

	dataToSign := append(pubKey[:], []byte(rootSigner.Reference())...)
	signature, err := rootSigner.Sign(dataToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign intermediate signer public key using root signer: %w", err)
	}

	intermediateSigner := signing.NewEd25519Signer(privKey, "ephemeral")

	issuerPublicKey, err := rootSigner.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get root signer public key: %w", err)
	}

	return &SignedProcessor{
		signerCertificate: &manifest.SimpleCertificate{
			PubKey:       pubKey,
			Sig:          signature,
			IssuerPubKey: issuerPublicKey,
			IssuerRef:    rootSigner.Reference(),
			SigAlgo:      rootSigner.Algorithm(),
		},
		signer:             intermediateSigner,
		manifestsGenerated: manifestsGenerated,
	}, nil
}

// Process implements ManifestProcessor for signed manifests
func (p *SignedProcessor) Process(dirPath string, m *manifest.Manifest, manifestName string) error {
	*p.manifestsGenerated = append(*p.manifestsGenerated, dirPath)

	manifestData, err := m.DataWithoutAuditor()
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	manifestSignature, err := p.signer.Sign(manifestData)
	if err != nil {
		return fmt.Errorf("failed to sign manifest: %w", err)
	}

	m.SetAuditedBy(p.signerCertificate, manifestSignature)
	return m.Save(filepath.Join(dirPath, manifestName))
}

// NewUnsignedProcessor creates a processor that saves manifests without signatures
func NewUnsignedProcessor(manifestsGenerated *[]string) *UnsignedProcessor {
	return &UnsignedProcessor{
		manifestsGenerated: manifestsGenerated,
	}
}

// Process implements ManifestProcessor for unsigned manifests
func (p *UnsignedProcessor) Process(dirPath string, m *manifest.Manifest, manifestName string) error {
	*p.manifestsGenerated = append(*p.manifestsGenerated, dirPath)
	m.SetAuditedBy(nil, nil)
	return m.Save(filepath.Join(dirPath, manifestName))
}
