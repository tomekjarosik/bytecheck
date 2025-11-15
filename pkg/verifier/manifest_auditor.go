package verifier

import (
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/issuer"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/signing"
)

type ManifestAuditor interface {
	Verify(m *manifest.Manifest) AuditResult
	GetIssuers() []issuer.Issuer
}

// SimpleManifestAuditor verifies the auditor's signature and certificate on a manifest.
// It also collects all unique issuer references from the certificates it successfully verifies.
type SimpleManifestAuditor struct {
	trustedIssuers map[string]issuer.Issuer
}

// NewSimpleManifestAuditor creates a new ManifestAuditor.
func NewSimpleManifestAuditor() *SimpleManifestAuditor {
	return &SimpleManifestAuditor{
		trustedIssuers: make(map[string]issuer.Issuer),
	}
}

// AuditResult holds the results of an audit verification.
type AuditResult struct {
	IsAudited bool
	Error     error
}

// GetIssuers returns a slice of all unique issuer references
// encountered during the verification process so far.
func (a *SimpleManifestAuditor) GetIssuers() []issuer.Issuer {
	refs := make([]issuer.Issuer, 0, len(a.trustedIssuers))
	for _, val := range a.trustedIssuers {
		refs = append(refs, val)
	}
	return refs
}

// Verify audits a given manifest, checking its signature and certificate through a two-step process.
func (a *SimpleManifestAuditor) Verify(m *manifest.Manifest) AuditResult {
	if m.Auditor == nil {
		return AuditResult{IsAudited: false}
	}

	auditorCert := m.GetAuditorCertificate()
	if auditorCert == nil {
		return AuditResult{IsAudited: true, Error: fmt.Errorf("auditor data present but certificate is missing")}
	}

	// Step 1: Verify the auditor's certificate.
	// This ensures the certificate itself is valid and has not been tampered with.
	cert := signing.NewSimpleCertificate(
		auditorCert.PublicKey(),
		auditorCert.IssuerPublicKey(),
		auditorCert.IssuerReference(),
		auditorCert.Signature())

	if !cert.Verify() {
		return AuditResult{IsAudited: true, Error: fmt.Errorf("auditor certificate is invalid: signature from issuer does not match")}
	}
	// Since the certificate is valid, remember the issuer's reference for later validation
	// against a trusted source (e.g., GitHub keys).
	a.trustedIssuers[cert.IssuerReference()] = issuer.Issuer{
		Reference: issuer.Reference(cert.IssuerReference()),
		PublicKey: cert.IssuerPublicKey()}

	// Step 2: Verify the manifest's signature.
	// This signature must be valid when checked against the certificate's public key.
	// This proves that the owner of the certificate's private key created the signature
	// for this manifest's content.
	manifestSignature := m.GetAuditorManifestSignature()
	dataToVerify, err := m.DataWithoutAuditor()
	if err != nil {
		return AuditResult{
			IsAudited: true,
			Error:     fmt.Errorf("failed to prepare manifest data for signature verification: %w", err),
		}
	}
	if !signing.VerifySignature(cert.PublicKey(), dataToVerify, manifestSignature) {
		return AuditResult{
			IsAudited: true,
			Error:     fmt.Errorf("manifest signature is invalid"),
		}
	}

	// If both cryptographic checks pass, the audit is successful.
	return AuditResult{IsAudited: true}
}
