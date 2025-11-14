package trust

import (
	"crypto/ed25519"
)

type IssuerReference string

// Issuer represents the combination of a reference string and the public key
// that was used in a manifest's certificate chain.
type Issuer struct {
	Reference IssuerReference
	PublicKey ed25519.PublicKey
}

type IssuerStatus struct {
	Issuer
	Supported bool
	Error     error
}

// Verifier defines the interface for verifying a collection of issuers
// against a trusted external source (like GitHub, a corporate key server, etc.).
type Verifier interface {
	// Verify takes a list of issuers found during manifest auditing and checks
	// if their public keys are valid according to the trusted source specified
	// in their reference string.
	Verify(issuers []Issuer) map[IssuerReference]IssuerStatus
	// Supports returns true if the verifier can handle the given reference scheme.
	Supports(reference IssuerReference) bool
}

// MultiSourceVerifier is a container for multiple Verifier implementations.
// It delegates verification to the first verifier that supports the issuer's reference scheme.
type MultiSourceVerifier struct {
	verifiers []Verifier
}

// NewMultiSourceVerifier creates a new verifier that can handle multiple trust sources.
func NewMultiSourceVerifier(verifiers ...Verifier) *MultiSourceVerifier {
	return &MultiSourceVerifier{verifiers: verifiers}
}

// Verify iterates through the issuers and delegates to the appropriate verifier.
func (v *MultiSourceVerifier) Verify(issuers []Issuer) map[IssuerReference]IssuerStatus {
	result := make(map[IssuerReference]IssuerStatus)
	for _, issuer := range issuers {
		result[issuer.Reference] = IssuerStatus{Issuer: issuer, Supported: false}
		for _, verifier := range v.verifiers {
			if verifier.Supports(issuer.Reference) {
				singleResult := verifier.Verify([]Issuer{issuer})
				result[issuer.Reference] = singleResult[issuer.Reference]
				break
			}
		}
	}
	return result
}

func (v *MultiSourceVerifier) Supports(reference IssuerReference) bool {
	return true
}
