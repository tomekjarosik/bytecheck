package issuer

import (
	"crypto/ed25519"
)

// Reference is key=val, like "github:tomekjarosik"

type Reference string

// Issuer represents the combination of a reference string and the public key
// that was used in a manifest's certificate chain.
type Issuer struct {
	Reference Reference
	PublicKey ed25519.PublicKey
}

type Status struct {
	Issuer
	Supported bool
	Error     error
}

// TrustVerifier defines the interface for verifying a collection of issuers
// against a trusted external source (like GitHub, a corporate key server, etc.).
type TrustVerifier interface {
	// Verify takes a list of issuers found during manifest auditing and checks
	// if their public keys are valid according to the trusted source specified
	// in their reference string.
	Verify(issuers []Issuer) map[Reference]Status
	// Supports returns true if the verifier can handle the given reference scheme.
	Supports(reference Reference) bool
}
