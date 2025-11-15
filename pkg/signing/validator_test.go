package signing

import (
	"crypto/ed25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	// Generate key pair
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testData := []byte("test message for signature verification")
	signature := ed25519.Sign(privKey, testData)

	// Test valid signature
	valid, err := VerifySignature(SignatureAlgorithmEd25519, pubKey, testData, signature)
	require.NoError(t, err)
	require.True(t, valid)

	// Test invalid signature (wrong data)
	wrongData := []byte("wrong message")
	valid, err = VerifySignature(SignatureAlgorithmEd25519, pubKey, wrongData, signature)
	require.NoError(t, err)
	require.False(t, valid)

	// Test invalid signature (corrupted signature)
	corruptedSignature := make([]byte, len(signature))
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 0xFF // Flip bits
	valid, err = VerifySignature(SignatureAlgorithmEd25519, pubKey, testData, corruptedSignature)
	require.NoError(t, err)
	require.False(t, valid)

	// Test with wrong public key
	wrongPubKey, _, _ := ed25519.GenerateKey(nil)
	valid, err = VerifySignature(SignatureAlgorithmEd25519, wrongPubKey, testData, signature)
	require.NoError(t, err)
	require.False(t, valid)
}
