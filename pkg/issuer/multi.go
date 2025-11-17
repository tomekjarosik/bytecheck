package issuer

// MultiSourceTrustVerifier is a container for multiple TrustVerifier implementations.
// It delegates verification to the first verifier that supports the issuer's reference scheme.
type MultiSourceTrustVerifier struct {
	verifiers []TrustVerifier
}

// NewMultiSourceVerifier creates a new verifier that can handle multiple trust sources.
func NewMultiSourceVerifier(verifiers ...TrustVerifier) *MultiSourceTrustVerifier {
	return &MultiSourceTrustVerifier{verifiers: verifiers}
}

// Verify iterates through the issuers and delegates to the appropriate verifier.
func (v *MultiSourceTrustVerifier) Verify(issuers []Issuer) map[Reference]Status {
	result := make(map[Reference]Status)
	for _, issuer := range issuers {
		result[issuer.Reference] = Status{Issuer: issuer, Supported: false}
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

func (v *MultiSourceTrustVerifier) Supports(reference Reference) bool {
	return true
}

// CreateVerifiersFromSchemes creates verifiers from scheme configurations
func CreateVerifiersFromSchemes(configs []SchemeConfig) []TrustVerifier {
	var verifiers []TrustVerifier
	for _, config := range configs {
		verifiers = append(verifiers, NewURLBasedTrustVerifier(config))
	}
	return verifiers
}

// CreateMultiVerifierFromSchemes creates a MultiSourceTrustVerifier from scheme configurations
func CreateMultiVerifierFromSchemes(configs []SchemeConfig) *MultiSourceTrustVerifier {
	verifiers := CreateVerifiersFromSchemes(configs)
	return NewMultiSourceVerifier(verifiers...)
}
