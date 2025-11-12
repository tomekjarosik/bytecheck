package certification

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestNewEd25519Signer(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	signer := NewEd25519Signer(pubKey, privateKey)

	if signer.PublicKey() == nil {
		t.Error("Public key should not be nil")
	}

	if len(signer.PublicKey()) != ed25519.PublicKeySize {
		t.Errorf("Public key size should be %d, got %d", ed25519.PublicKeySize, len(signer.PublicKey()))
	}
}

func TestEd25519Signer_Sign(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	signer := NewEd25519Signer(pubKey, privateKey)

	testData := []byte("test message to sign")
	signature, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Signature size should be %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Verify the signature
	if !ed25519.Verify(signer.PublicKey(), testData, signature) {
		t.Error("Signature verification failed")
	}
}

func TestEd25519Signer_Close(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	signer := NewEd25519Signer(pubKey, privateKey)

	err = signer.Close()
	if err != nil {
		t.Errorf("Close should not return error, got: %v", err)
	}
}

func TestNewEd25519SignerFromFile(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "test_key")

	// Generate a key pair and write the private key to file
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	err = os.WriteFile(keyFile, privateKey, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create signer from file
	signer, err := NewEd25519SignerFromFile(keyFile)
	if err != nil {
		t.Fatalf("Failed to create signer from file: %v", err)
	}

	// Test that public key matches
	expectedPublicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("Failed to extract public key")
	}

	if !signer.PublicKey().Equal(expectedPublicKey) {
		t.Error("Public key doesn't match expected key")
	}

	// Test signing
	testData := []byte("test message")
	signature, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if !ed25519.Verify(signer.PublicKey(), testData, signature) {
		t.Error("Signature verification failed")
	}
}

func TestNewEd25519SignerFromFile_FileNotFound(t *testing.T) {
	_, err := NewEd25519SignerFromFile("nonexistent_file")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestNewEd25519SignerFromFile_InvalidKeySize(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "invalid_key")

	// Write invalid key data (wrong size)
	invalidKey := make([]byte, 16) // Too short
	err := os.WriteFile(keyFile, invalidKey, 0600)
	if err != nil {
		t.Fatalf("Failed to write invalid key file: %v", err)
	}

	_, err = NewEd25519SignerFromFile(keyFile)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestNewEd25519SignerFromFile_EmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "empty_key")

	// Write empty file
	err := os.WriteFile(keyFile, []byte{}, 0600)
	if err != nil {
		t.Fatalf("Failed to write empty key file: %v", err)
	}

	_, err = NewEd25519SignerFromFile(keyFile)
	if err == nil {
		t.Error("Expected error for empty key file")
	}
}

func TestEd25519Signer_SignConsistency(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	signer := NewEd25519Signer(pubKey, privateKey)

	testData := []byte("consistent signing test")

	// Sign the same data multiple times
	sig1, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data first time: %v", err)
	}

	sig2, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data second time: %v", err)
	}

	// Ed25519 signatures should be deterministic
	if string(sig1) != string(sig2) {
		t.Error("Ed25519 signatures should be deterministic")
	}
}

func TestEd25519Signer_SignEmptyData(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	signer := NewEd25519Signer(pubKey, privateKey)

	signature, err := signer.Sign([]byte{})
	if err != nil {
		t.Fatalf("Failed to sign empty data: %v", err)
	}

	if !ed25519.Verify(signer.PublicKey(), []byte{}, signature) {
		t.Error("Failed to verify signature of empty data")
	}
}
