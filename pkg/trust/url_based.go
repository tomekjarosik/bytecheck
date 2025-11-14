package trust

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
)

// URLBasedVerifier validates issuers against public keys hosted at a given URL template.
type URLBasedVerifier struct {
	client      *http.Client
	scheme      string
	urlTemplate string
}

// NewURLBasedVerifier creates a generic verifier that fetches keys from a URL.
// The urlTemplate should be a format string that accepts one argument (e.g., "https://example.com/keys/%s").
func NewURLBasedVerifier(scheme string, urlTemplate string) *URLBasedVerifier {
	return &URLBasedVerifier{
		client:      &http.Client{},
		scheme:      scheme,
		urlTemplate: urlTemplate,
	}
}

// NewGitHubIssuerVerifier creates a new verifier specifically for GitHub-hosted keys.
func NewGitHubIssuerVerifier() *URLBasedVerifier {
	return NewURLBasedVerifier("github:", "https://github.com/%s.keys")
}

// Supports returns true for references that match the verifier's configured scheme.
func (v *URLBasedVerifier) Supports(reference IssuerReference) bool {
	return strings.HasPrefix(string(reference), v.scheme)
}

// Verify checks if the public keys of the given issuers are present in the trusted source.
// It returns a map where each key is an issuer reference and the value is an IssuerStatus
func (v *URLBasedVerifier) Verify(issuers []Issuer) map[IssuerReference]IssuerStatus {
	results := make(map[IssuerReference]IssuerStatus)
	issuersByRef := make(map[IssuerReference][]Issuer)
	for _, issuer := range issuers {
		if v.Supports(issuer.Reference) {
			issuersByRef[issuer.Reference] = append(issuersByRef[issuer.Reference], issuer)
		}
	}

	for ref, issuerGroup := range issuersByRef {
		trustedKeys, err := v.fetchPublicKeys(ref)
		if err != nil {
			results[ref] = IssuerStatus{
				Issuer:    issuerGroup[0],
				Supported: true,
				Error:     fmt.Errorf("could not fetch keys for '%s': %w", ref, err),
			}
			continue
		}

		// Check each issuer's public key against the trusted set.
		allKeysValid := true
		for _, issuer := range issuerGroup {
			if !isKeyInSet(issuer.PublicKey, trustedKeys) {
				allKeysValid = false
				break // Found one invalid key, no need to check others for this ref.
			}
		}

		if !allKeysValid {
			results[ref] = IssuerStatus{
				Issuer:    issuerGroup[0],
				Supported: true,
				Error:     fmt.Errorf("one or more public keys for issuer '%s' not found in trusted source", ref),
			}
			continue
		}

		results[ref] = IssuerStatus{
			Issuer:    issuerGroup[0],
			Supported: true,
			Error:     nil,
		}
	}

	for _, issuer := range issuers {
		if _, ok := results[issuer.Reference]; !ok {
			results[issuer.Reference] = IssuerStatus{Issuer: issuer, Supported: false, Error: nil}
		}
	}

	return results
}

// fetchPublicKeys retrieves and parses public keys from the configured URL template.
func (v *URLBasedVerifier) fetchPublicKeys(reference IssuerReference) (map[string]struct{}, error) {
	identifier := strings.TrimPrefix(string(reference), v.scheme)
	if identifier == "" {
		return nil, fmt.Errorf("invalid reference: missing identifier in '%s'", reference)
	}

	url := fmt.Sprintf(v.urlTemplate, identifier)
	resp, err := v.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch URL %s: received status %s", url, resp.Status)
	}

	// Parse the keys from the response body.
	scanner := bufio.NewScanner(resp.Body)
	keySet := make(map[string]struct{})
	for scanner.Scan() {
		pk, _, _, _, err := ssh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			continue // Ignore lines that don't parse as valid keys.
		}

		cryptoPubKey, ok := pk.(ssh.CryptoPublicKey)
		if !ok {
			continue
		}
		ed25519PubKey, ok := cryptoPubKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			continue // Key is valid but not ed25519, so we skip it.
		}
		keySet[string(ed25519PubKey)] = struct{}{}
	}

	return keySet, scanner.Err()
}

// isKeyInSet checks if a given ed25519 public key exists in a set of keys.
func isKeyInSet(key ed25519.PublicKey, keySet map[string]struct{}) bool {
	_, found := keySet[string(key)]
	return found
}
