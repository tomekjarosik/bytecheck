package issuer

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
	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "github",
		Template: "https://github.com/%s.keys",
	})

	tests := []struct {
		name      string
		reference Reference
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
	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "test",
		Template: server.URL + "/%s",
	})
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: Reference("test:valid-issuer"),
			PublicKey: publicKey1,
		},
		{
			Reference: Reference("test:valid-issuer"),
			PublicKey: publicKey2,
		},
		{
			Reference: Reference("unknown:scheme"),
			PublicKey: publicKey1,
		},
	}

	results := verifier.Verify(issuers)

	// Verify results
	require.Contains(t, results, Reference("test:valid-issuer"))
	require.Contains(t, results, Reference("unknown:scheme"))

	// Check successful verification
	status := results["test:valid-issuer"]
	assert.True(t, status.Supported)
	assert.NoError(t, status.Error)
	assert.Equal(t, issuers[0].Reference, status.Issuer.Reference)

	// Check unsupported scheme
	status = results[Reference("unknown:scheme")]
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

	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "test",
		Template: server.URL + "/%s",
	})
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: Reference("test:issuer"),
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

			verifier := NewURLBasedTrustVerifier(SchemeConfig{
				Name:     "test",
				Template: server.URL + "/%s",
			})
			verifier.client = server.Client()

			issuers := []Issuer{
				{
					Reference: Reference("test:issuer"),
					PublicKey: publicKey,
				},
			}

			results := verifier.Verify(issuers)
			status := results[Reference("test:issuer")]

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

	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "test",
		Template: server.URL + "/%s",
	})
	verifier.client = server.Client()

	// Test with empty identifier after scheme prefix
	issuers := []Issuer{
		{
			Reference: Reference("test:"), // Empty identifier
			PublicKey: publicKey,
		},
	}

	results := verifier.Verify(issuers)
	status := results[Reference("test:")]

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

	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "test",
		Template: server.URL + "/%s",
	})
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: Reference("test:issuer"),
			PublicKey: ed25519PubKey,
		},
	}

	results := verifier.Verify(issuers)
	status := results[Reference("test:issuer")]

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

	assert.Equal(t, "github", verifier.schemeConfig.Name)
	assert.Equal(t, "https://github.com/%s.keys", verifier.schemeConfig.Template)
	assert.NotNil(t, verifier.client)
}

// TestURLBasedVerifier_Verify_StaticURL tests verification with a static URL template (no %s)
func TestURLBasedVerifier_Verify_StaticURL(t *testing.T) {
	// Generate test key
	publicKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate key pair")

	// Create a test server that returns the public key
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that we're hitting the expected static endpoint
		assert.Equal(t, "/static/keys.txt", r.URL.Path)

		// Return the public key in SSH format
		sshPub, err := ssh.NewPublicKey(publicKey)
		require.NoError(t, err)
		w.Write(ssh.MarshalAuthorizedKey(sshPub))
	}))
	defer server.Close()

	// Create verifier with static URL template (no %s)
	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "static",
		Template: server.URL + "/static/keys.txt", // No %s placeholder
	})
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: Reference("static:any-identifier"), // Identifier is ignored for static URLs
			PublicKey: publicKey,
		},
	}

	results := verifier.Verify(issuers)

	// Verify results
	require.Contains(t, results, Reference("static:any-identifier"))
	status := results["static:any-identifier"]
	assert.True(t, status.Supported)
	assert.NoError(t, status.Error)
	assert.Equal(t, issuers[0].Reference, status.Issuer.Reference)
}

// TestURLBasedVerifier_Verify_MultipleIssuersSameStaticURL tests multiple issuers using the same static URL
func TestURLBasedVerifier_Verify_MultipleIssuersSameStaticURL(t *testing.T) {
	// Generate test keys
	publicKey1, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	publicKey2, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create a test server that returns multiple public keys
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

	// Create verifier with static URL template
	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "team",
		Template: server.URL + "/team-keys.txt", // No %s placeholder
	})
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: Reference("team:alice"), // Identifier ignored
			PublicKey: publicKey1,
		},
		{
			Reference: Reference("team:bob"), // Identifier ignored
			PublicKey: publicKey2,
		},
		{
			Reference: Reference("team:charlie"), // Identifier ignored
			PublicKey: publicKey1,                // Same key as alice
		},
	}

	results := verifier.Verify(issuers)

	// All should be trusted since both keys are in the static key file
	for _, issuer := range issuers {
		status := results[issuer.Reference]
		assert.True(t, status.Supported)
		assert.NoError(t, status.Error)
	}
}

// TestURLBasedVerifier_Verify_StaticURLWithMissingKey tests static URL where key is not found
func TestURLBasedVerifier_Verify_StaticURLWithMissingKey(t *testing.T) {
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

	verifier := NewURLBasedTrustVerifier(SchemeConfig{
		Name:     "static",
		Template: server.URL + "/keys.pub", // No %s
	})
	verifier.client = server.Client()

	issuers := []Issuer{
		{
			Reference: Reference("static:user123"), // Identifier ignored
			PublicKey: untrustedKey,                // This key is not in the static key file
		},
	}

	results := verifier.Verify(issuers)

	status := results["static:user123"]
	require.True(t, status.Supported)
	require.Error(t, status.Error)
	assert.Contains(t, status.Error.Error(), "not found in trusted source")
}
