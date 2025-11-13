package verify

import (
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/certification"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
)

type ManifestAuditor interface {
	Verify(m *manifest.Manifest) AuditResult
}

// ManifestAuditor verifies the auditor's signature and certificate on a manifest.
type SimpleManifestAuditor struct {
}

// NewManifestAuditor creates a new ManifestAuditor.
func NewSimpleManifestAuditor() *SimpleManifestAuditor {
	return &SimpleManifestAuditor{}
}

// AuditResult holds the results of an audit verification.
type AuditResult struct {
	IsAudited bool
	Error     error
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

	// --- Two-step Verification Process ---
	cert := certification.NewSimpleCertificate(auditorCert.PublicKey(),
		auditorCert.IssuerPublicKey(),
		auditorCert.IssuerReference(),
		auditorCert.Signature())

	if !cert.Verify() {
		return AuditResult{IsAudited: true, Error: fmt.Errorf("auditor certificate is invalid: signature from issuer does not match")}
	}

	// TODO(tjarosik):
	// At this point, the certificate is cryptographically valid. A complete solution would
	// also check if the issuer's public key is in a predefined list of trusted keys,
	// but that is a policy decision outside the scope of this cryptographic check.

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
	if !certification.VerifySignature(cert.PublicKey(), dataToVerify, manifestSignature) {
		return AuditResult{
			IsAudited: true,
			Error:     fmt.Errorf("manifest signature is invalid"),
		}
	}

	// If both cryptographic checks pass, the audit is successful.
	return AuditResult{IsAudited: true}
}
