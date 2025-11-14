package certification

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSigner is a helper function to create a new Ed25519Signer for testing.
func newTestSigner(t *testing.T, reference string) Signer {
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to create key pair")
	signer := NewEd25519Signer(privateKey, reference)
	require.NotNil(t, signer)
	require.True(t, pubKey.Equal(signer.PublicKey()))
	return signer
}

func TestNewEd25519Signer(t *testing.T) {
	signer := newTestSigner(t, "test-reference")
	assert.NotNil(t, signer.PublicKey())
	assert.Len(t, signer.PublicKey(), ed25519.PublicKeySize)
	assert.Equal(t, "test-reference", signer.Reference())
}

func TestEd25519Signer_Sign(t *testing.T) {
	signer := newTestSigner(t, "test-reference")
	testData := []byte("test message to sign")

	signature, err := signer.Sign(testData)
	require.NoError(t, err, "Failed to sign data")

	assert.Len(t, signature, ed25519.SignatureSize)
	assert.True(t, ed25519.Verify(signer.PublicKey(), testData, signature), "Signature verification failed")
}

func TestEd25519Signer_Close(t *testing.T) {
	signer := newTestSigner(t, "test-reference")
	assert.NoError(t, signer.Close(), "Close should not return an error")
}

func TestNewEd25519SignerFromFile(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "test_key")
	reference := "file-key-reference"

	privateKey, _, err := GenerateKeyPair(keyFile, keyFile+".pub")
	require.NoError(t, err)

	signer, err := NewEd25519SignerFromFile(keyFile, reference)
	require.NoError(t, err, "Failed to create signer from file")

	expectedPublicKey := privateKey.Public().(ed25519.PublicKey)
	assert.True(t, signer.PublicKey().Equal(expectedPublicKey), "Public key doesn't match expected key")
	assert.Equal(t, reference, signer.Reference())

	testData := []byte("test message")
	signature, err := signer.Sign(testData)
	require.NoError(t, err, "Failed to sign data")

	assert.True(t, ed25519.Verify(signer.PublicKey(), testData, signature), "Signature verification failed")
}

func TestNewEd25519SignerFromFile_Failures(t *testing.T) {
	t.Run("File not found", func(t *testing.T) {
		_, err := NewEd25519SignerFromFile("nonexistent_file", "test")
		assert.Error(t, err)
	})

	t.Run("Invalid key format", func(t *testing.T) {
		keyFile := filepath.Join(t.TempDir(), "invalid_key")
		err := os.WriteFile(keyFile, []byte("this is not a valid key"), 0600)
		require.NoError(t, err)
		_, err = NewEd25519SignerFromFile(keyFile, "test")
		assert.Error(t, err)
	})

	t.Run("Empty key file", func(t *testing.T) {
		keyFile := filepath.Join(t.TempDir(), "empty_key")
		err := os.WriteFile(keyFile, []byte{}, 0600)
		require.NoError(t, err)
		_, err = NewEd25519SignerFromFile(keyFile, "test")
		assert.Error(t, err)
	})
}

func TestEd25519Signer_SignConsistency(t *testing.T) {
	signer := newTestSigner(t, "test-reference")
	testData := []byte("consistent signing test")

	sig1, err := signer.Sign(testData)
	require.NoError(t, err)

	sig2, err := signer.Sign(testData)
	require.NoError(t, err)

	assert.Equal(t, sig1, sig2, "Ed25519 signatures should be deterministic")
}

func TestEd25519Signer_SignEmptyData(t *testing.T) {
	signer := newTestSigner(t, "test-reference")
	emptyData := []byte{}

	signature, err := signer.Sign(emptyData)
	require.NoError(t, err, "Failed to sign empty data")

	assert.True(t, ed25519.Verify(signer.PublicKey(), emptyData, signature), "Failed to verify signature of empty data")
}
