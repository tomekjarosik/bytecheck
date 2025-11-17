package issuer

// NewGitHubIssuerVerifier creates a new verifier specifically for GitHub-hosted keys.
func NewGitHubIssuerVerifier() *URLBasedVerifier {
	return NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "github",
		Template: "https://github.com/%s.keys",
	})
}
