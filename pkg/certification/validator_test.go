package certification

import (
	"crypto/ed25519"
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
	if !VerifySignature(pubKey, testData, signature) {
		t.Error("Valid signature verification failed")
	}

	// Test invalid signature (wrong data)
	wrongData := []byte("wrong message")
	if VerifySignature(pubKey, wrongData, signature) {
		t.Error("Invalid signature verification should fail")
	}

	// Test invalid signature (corrupted signature)
	corruptedSignature := make([]byte, len(signature))
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 0xFF // Flip bits
	if VerifySignature(pubKey, testData, corruptedSignature) {
		t.Error("Corrupted signature verification should fail")
	}

	// Test with wrong public key
	wrongPubKey, _, _ := ed25519.GenerateKey(nil)
	if VerifySignature(wrongPubKey, testData, signature) {
		t.Error("Wrong public key verification should fail")
	}
}
