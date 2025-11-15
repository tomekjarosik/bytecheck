package issuer

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCustomURLVerifier_NewCustomURLVerifier(t *testing.T) {
	// Test when environment variable is not set
	t.Run("returns nil when env not set", func(t *testing.T) {
		os.Unsetenv(CustomSchemeEnvVarName)
		verifier := NewCustomURLVerifier()
		assert.Nil(t, verifier.URLBasedVerifier)
	})

	// Test when environment variable is set
	t.Run("creates verifier when env is set", func(t *testing.T) {
		os.Setenv(CustomSchemeEnvVarName, "https://example.com/keys/%s")
		defer os.Unsetenv(CustomSchemeEnvVarName)

		v := NewCustomURLVerifier()
		require.NotNil(t, v)
		assert.Equal(t, "custom:", v.scheme)
		assert.Equal(t, "https://example.com/keys/%s", v.urlTemplate)
	})
}

func TestCustomURLVerifier_Supports(t *testing.T) {
	os.Setenv(CustomSchemeEnvVarName, "https://example.com/keys/%s")
	defer os.Unsetenv(CustomSchemeEnvVarName)

	verifier := NewCustomURLVerifier()
	require.NotNil(t, verifier)

	tests := []struct {
		name      string
		reference Reference
		expected  bool
	}{
		{
			name:      "supports custom scheme",
			reference: "custom:my-issuer",
			expected:  true,
		},
		{
			name:      "does not support other schemes",
			reference: "github:owner/repo",
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

func TestCustomURLVerifier_WithFileURL(t *testing.T) {
	// Create a temporary file with a test public key
	publicKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "test-issuer.pub")

	// Write the public key in SSH format
	sshPub, err := ssh.NewPublicKey(publicKey)
	require.NoError(t, err)
	err = os.WriteFile(keyFile, ssh.MarshalAuthorizedKey(sshPub), 0644)
	require.NoError(t, err)

	// Set environment variable to use file URL
	os.Setenv(CustomSchemeEnvVarName,
		strings.Replace("file://"+keyFile, "test-issuer.pub", "%s.pub", 1))
	defer os.Unsetenv(CustomSchemeEnvVarName)

	verifier := NewCustomURLVerifier()
	require.NotNil(t, verifier)

	issuers := []Issuer{
		{
			Reference: Reference("custom:test-issuer"),
			PublicKey: publicKey,
		},
	}

	results := verifier.Verify(issuers)
	require.Contains(t, results, Reference("custom:test-issuer"))

	status := results["custom:test-issuer"]
	assert.True(t, status.Supported)
	assert.NoError(t, status.Error)
}
