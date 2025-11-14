package trust

import (
	"crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestURLBasedVerifier_Supports tests the Supports method
func TestURLBasedVerifier_Supports(t *testing.T) {
	verifier := NewURLBasedVerifier("github:", "https://github.com/%s.keys")

	tests := []struct {
		name      string
		reference IssuerReference
		expected  bool
	}{
		{
			name:      "supports matching scheme",
			reference: "github:owner/repo",
			expected:  true,
		},
		{
			name:      "does not support different scheme",
			reference: "gitlab:owner/repo",
			expected:  false,
		},
		{
			name:      "does not support empty reference",
			reference: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.Supports(tt.reference)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestURLBasedVerifier_Verify_Success tests successful verification
func TestURLBasedVerifier_Verify_Success(t *testing.T) {
	// Generate test keys
	publicKey1, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate key pair 1")

	publicKey2, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate key pair 2")

	// Create a test server that returns the public keys
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return both public keys in SSH format
		sshPub1, err := ssh.NewPublicKey(publicKey1)
		require.NoError(t, err)
		sshPub2, err := ssh.NewPublicKey(publicKey2)
		require.NoError(t, err)

		response := string(ssh.MarshalAuthorizedKey(sshPub1)) + "\n" +
			string(ssh.MarshalAuthorizedKey(sshPub2)) + "\n"
		w.Write([]byte(response))
	}))
	defer server.Close()

	// Create verifier with test server URL
	verifier := NewURLBasedVerifier("test:", server.URL+"/%s")
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: IssuerReference("test:valid-issuer"),
			PublicKey: publicKey1,
		},
		{
			Reference: IssuerReference("test:valid-issuer"),
			PublicKey: publicKey2,
		},
		{
			Reference: IssuerReference("unknown:scheme"),
			PublicKey: publicKey1,
		},
	}

	results := verifier.Verify(issuers)

	// Verify results
	require.Contains(t, results, IssuerReference("test:valid-issuer"))
	require.Contains(t, results, IssuerReference("unknown:scheme"))

	// Check successful verification
	status := results[IssuerReference("test:valid-issuer")]
	assert.True(t, status.Supported)
	assert.NoError(t, status.Error)
	assert.Equal(t, issuers[0].Reference, status.Issuer.Reference)

	// Check unsupported scheme
	status = results[IssuerReference("unknown:scheme")]
	assert.False(t, status.Supported)
	assert.NoError(t, status.Error)
}

// TestURLBasedVerifier_Verify_KeyNotFound tests when public key is not in trusted set
func TestURLBasedVerifier_Verify_KeyNotFound(t *testing.T) {
	// Generate keys
	trustedKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	untrustedKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return only the trusted key
		sshPub, err := ssh.NewPublicKey(trustedKey)
		require.NoError(t, err)
		w.Write(ssh.MarshalAuthorizedKey(sshPub))
	}))
	defer server.Close()

	verifier := NewURLBasedVerifier("test:", server.URL+"/%s")
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: IssuerReference("test:issuer"),
			PublicKey: untrustedKey, // This key is not in the trusted set
		},
	}

	results := verifier.Verify(issuers)

	status := results["test:issuer"]
	require.True(t, status.Supported)
	require.Error(t, status.Error)
	assert.Contains(t, status.Error.Error(), "one or more public keys for issuer 'test:issuer' not found in trusted source")
}

// TestURLBasedVerifier_Verify_HTTPError tests HTTP error scenarios
func TestURLBasedVerifier_Verify_HTTPError(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		expectedError string
	}{
		{
			name: "server returns 404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedError: "failed to fetch URL",
		},
		{
			name: "server returns 500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "failed to fetch URL",
		},
		{
			name: "server connection error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Simulate connection close
				hj, ok := w.(http.Hijacker)
				if ok {
					conn, _, _ := hj.Hijack()
					conn.Close()
				}
			},
			expectedError: "failed to fetch URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			verifier := NewURLBasedVerifier("test:", server.URL+"/%s")
			verifier.client = server.Client()

			issuers := []Issuer{
				{
					Reference: IssuerReference("test:issuer"),
					PublicKey: publicKey,
				},
			}

			results := verifier.Verify(issuers)
			status := results[IssuerReference("test:issuer")]

			require.True(t, status.Supported)
			require.Error(t, status.Error)
			assert.Contains(t, status.Error.Error(), tt.expectedError)
		})
	}
}

// TestURLBasedVerifier_Verify_InvalidReference tests invalid reference handling
func TestURLBasedVerifier_Verify_InvalidReference(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	verifier := NewURLBasedVerifier("test:", server.URL+"/%s")
	verifier.client = server.Client()

	// Test with empty identifier after scheme prefix
	issuers := []Issuer{
		{
			Reference: IssuerReference("test:"), // Empty identifier
			PublicKey: publicKey,
		},
	}

	results := verifier.Verify(issuers)
	status := results[IssuerReference("test:")]

	require.True(t, status.Supported)
	require.Error(t, status.Error)
	assert.Contains(t, status.Error.Error(), "invalid reference")
}

// TestURLBasedVerifier_Verify_MixedKeyTypes tests handling of non-ed25519 keys in response
func TestURLBasedVerifier_Verify_MixedKeyTypes(t *testing.T) {
	ed25519PubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a mix of valid ed25519 key and some invalid data
		sshPub, err := ssh.NewPublicKey(ed25519PubKey)
		require.NoError(t, err)

		response := string(ssh.MarshalAuthorizedKey(sshPub)) + "\n" +
			"ssh-rsa AAAAB3NzaC1yc2E...\n" + // Different key type
			"invalid-key-data\n" // Completely invalid

		w.Write([]byte(response))
	}))
	defer server.Close()

	verifier := NewURLBasedVerifier("test:", server.URL+"/%s")
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: IssuerReference("test:issuer"),
			PublicKey: ed25519PubKey,
		},
	}

	results := verifier.Verify(issuers)
	status := results[IssuerReference("test:issuer")]

	// Should still work - only ed25519 keys are considered
	assert.True(t, status.Supported)
	assert.NoError(t, status.Error)
}

// TestIsKeyInSet tests the helper function
func TestIsKeyInSet(t *testing.T) {
	key1 := ed25519.PublicKey("public-key-1")
	key2 := ed25519.PublicKey("public-key-2")

	keySet := map[string]struct{}{
		"public-key-1": {},
		"public-key-3": {},
	}

	assert.True(t, isKeyInSet(key1, keySet), "key1 should be found in set")
	assert.False(t, isKeyInSet(key2, keySet), "key2 should not be found in set")
}

// TestNewGitHubIssuerVerifier tests the GitHub-specific constructor
func TestNewGitHubIssuerVerifier(t *testing.T) {
	verifier := NewGitHubIssuerVerifier()

	assert.Equal(t, "github:", verifier.scheme)
	assert.Equal(t, "https://github.com/%s.keys", verifier.urlTemplate)
	assert.NotNil(t, verifier.client)
}
