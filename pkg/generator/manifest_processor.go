package generator

import (
	"crypto/ed25519"
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/certification"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"path/filepath"
)

type ManifestProcessor interface {
	Process(dirPath string, m *manifest.Manifest, manifestName string) error
}

// SignedProcessor handles manifests with cryptographic signatures
type SignedProcessor struct {
	certificate        certification.Certificate
	signer             certification.Signer
	manifestsGenerated *[]string
}

// UnsignedProcessor handles manifests without signatures
type UnsignedProcessor struct {
	manifestsGenerated *[]string
}

// NewSignedProcessor creates a processor that signs manifests
func NewSignedProcessor(rootSigner certification.Signer, manifestsGenerated *[]string) (*SignedProcessor, error) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral signing key: %w", err)
	}

	cert, err := certification.IssueCertificate(pubKey, rootSigner, "todo")
	if err != nil {
		return nil, fmt.Errorf("failed to issue auditor certificate: %w", err)
	}

	intermediateSigner := certification.NewEd25519Signer(privKey, "ephemeral")

	return &SignedProcessor{
		certificate:        cert,
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

	m.SetAuditedBy(p.certificate, manifestSignature)
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
