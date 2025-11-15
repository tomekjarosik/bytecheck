package issuer

import (
	"os"
)

var CustomScheme = "custom:"
var CustomSchemeEnvVarName = "BYTECHECK_CUSTOM_AUDITOR_VERIFIER_URL_TEMPLATE"

// CustomURLVerifier uses URLBasedVerifier for the "custom" scheme with any URL template
// configured via environment variable BYTECHECK_CUSTOM_AUDITOR_VERIFIER_URL_TEMPLATE
type CustomURLVerifier struct {
	*URLBasedVerifier
}

// NewCustomURLVerifier creates a new verifier for the "custom" scheme that uses
// the URL template from BYTECHECK_CUSTOM_AUDITOR_VERIFIER_URL_TEMPLATE environment variable.
// Returns nil if the environment variable is not set.
func NewCustomURLVerifier() *CustomURLVerifier {
	urlTemplate := os.Getenv(CustomSchemeEnvVarName)
	if urlTemplate == "" {
		return &CustomURLVerifier{nil}
	}

	return &CustomURLVerifier{
		URLBasedVerifier: NewURLBasedVerifier(CustomScheme, urlTemplate),
	}
}

// Supports returns true for references that use the "custom:" scheme
func (v *CustomURLVerifier) Supports(reference Reference) bool {
	if v.URLBasedVerifier == nil {
		return false
	}
	return v.URLBasedVerifier.Supports(reference)
}

// Verify delegates to the underlying URLBasedVerifier
func (v *CustomURLVerifier) Verify(issuers []Issuer) map[Reference]Status {
	return v.URLBasedVerifier.Verify(issuers)
}
