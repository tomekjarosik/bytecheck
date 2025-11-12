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

func TestVerifyCertificateChain_EmptyChain(t *testing.T) {
	err := VerifyCertificateChain([]Certificate{})
	if err == nil {
		t.Error("Empty certificate chain should return error")
	}
}

func TestVerifyCertificateChain_SingleRootCertificate(t *testing.T) {
	// Create a root signer
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	rootSigner := NewEd25519Signer(pubKey, privateKey)

	// Create root certificate
	rootCert, err := CreateRootCertificate("test", rootSigner)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	// Verify single certificate chain
	err = VerifyCertificateChain([]Certificate{rootCert})
	if err != nil {
		t.Errorf("Valid single root certificate chain should not return error: %v", err)
	}
}

func TestVerifyCertificateChain_InvalidRootCertificate(t *testing.T) {
	// Create invalid root certificate (not self-signed)
	rootPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	issuerPubKey, issuerPrivKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	signature := ed25519.Sign(issuerPrivKey, rootPubKey)
	invalidRootCert := NewSimpleCertificate("test", rootPubKey, issuerPubKey, signature)

	err = VerifyCertificateChain([]Certificate{invalidRootCert})
	if err == nil {
		t.Error("Invalid root certificate should return error")
	}
}

func TestVerifyCertificateChain_InvalidRootSignature(t *testing.T) {
	// Create root certificate with invalid signature
	rootPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate root key: %v", err)
	}

	// Create invalid signature
	invalidSignature := make([]byte, ed25519.SignatureSize)
	invalidRootCert := NewSimpleCertificate("test", rootPubKey, rootPubKey, invalidSignature)

	err = VerifyCertificateChain([]Certificate{invalidRootCert})
	if err == nil {
		t.Error("Root certificate with invalid signature should return error")
	}
}

func TestVerifyCertificateChain_ValidTwoCertificateChain(t *testing.T) {
	// Create root signer and certificate
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	rootSigner := NewEd25519Signer(pubKey, privateKey)

	rootCert, err := CreateRootCertificate("test", rootSigner)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	// Create intermediate certificate
	intermediatePubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	intermediateCert, err := IssueCertificate("test", intermediatePubKey, rootSigner)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	// Verify two-certificate chain
	chain := []Certificate{rootCert, intermediateCert}
	err = VerifyCertificateChain(chain)
	if err != nil {
		t.Errorf("Valid two-certificate chain should not return error: %v", err)
	}
}

func TestVerifyCertificateChain_InvalidChainLinking(t *testing.T) {
	// Create two independent root certificates
	pubKey1, privateKey1, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	rootSigner1 := NewEd25519Signer(pubKey1, privateKey1)

	rootCert1, err := CreateRootCertificate("test", rootSigner1)
	if err != nil {
		t.Fatalf("Failed to create root certificate 1: %v", err)
	}

	pubKey2, privateKey2, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	rootSigner2 := NewEd25519Signer(pubKey2, privateKey2)

	// Create certificate signed by signer2
	leafPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	leafCert, err := IssueCertificate("test", leafPubKey, rootSigner2)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Try to verify chain where certificates don't link
	chain := []Certificate{rootCert1, leafCert}
	err = VerifyCertificateChain(chain)
	if err == nil {
		t.Error("Invalid certificate chain should return error")
	}
}

func TestVerifyCertificateChain_InvalidIntermediateSignature(t *testing.T) {
	// Create two independent root certificates
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	rootSigner := NewEd25519Signer(pubKey, privateKey)

	rootCert, err := CreateRootCertificate("test", rootSigner)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	// Create intermediate certificate with invalid signature
	intermediatePubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate intermediate key: %v", err)
	}

	invalidSignature := make([]byte, ed25519.SignatureSize)
	invalidIntermediateCert := NewSimpleCertificate("test", intermediatePubKey, rootSigner.PublicKey(), invalidSignature)

	// Try to verify chain with invalid intermediate signature
	chain := []Certificate{rootCert, invalidIntermediateCert}
	err = VerifyCertificateChain(chain)
	if err == nil {
		t.Error("Certificate chain with invalid intermediate signature should return error")
	}
}

func TestVerifyCertificateChain_LongValidChain(t *testing.T) {
	// Create two independent root certificates
	pubKey1, privateKey1, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	rootSigner := NewEd25519Signer(pubKey1, privateKey1)

	rootCert, err := CreateRootCertificate("test", rootSigner)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	chain := []Certificate{rootCert}
	currentSigner := rootSigner

	// Create a chain of 5 certificates
	for i := 0; i < 4; i++ {
		// Create two independent root certificates
		pubKey1, privateKey1, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("Failed to create key pair: %v", err)
		}
		nextSigner := NewEd25519Signer(pubKey1, privateKey1)

		nextCert, err := IssueCertificate("test", nextSigner.PublicKey(), currentSigner)
		if err != nil {
			t.Fatalf("Failed to create certificate %d: %v", i+1, err)
		}

		chain = append(chain, nextCert)
		currentSigner = nextSigner
	}

	// Verify the long chain
	err = VerifyCertificateChain(chain)
	if err != nil {
		t.Errorf("Valid long certificate chain should not return error: %v", err)
	}
}

func TestVerifySignature_EdgeCases(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test with empty data
	emptyData := []byte{}
	emptySignature := ed25519.Sign(privKey, emptyData)
	if !VerifySignature(pubKey, emptyData, emptySignature) {
		t.Error("Empty data signature verification failed")
	}

	// Test with nil data
	if VerifySignature(pubKey, nil, emptySignature) {
		t.Error("Nil data should not verify against empty data signature")
	}

	// Test with wrong signature length
	shortSignature := make([]byte, 10)
	if VerifySignature(pubKey, []byte("test"), shortSignature) {
		t.Error("Short signature should not verify")
	}
}
