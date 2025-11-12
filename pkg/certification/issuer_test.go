package certification

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestNewSimpleCertificate(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	issuerPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate issuer key pair: %v", err)
	}

	signature := ed25519.Sign(privKey, pubKey)

	cert := NewSimpleCertificate("test", pubKey, issuerPubKey, signature)

	if !cert.PublicKey().Equal(pubKey) {
		t.Error("Public key mismatch")
	}
	if !cert.IssuerPublicKey().Equal(issuerPubKey) {
		t.Error("Issuer public key mismatch")
	}
	if string(cert.Signature()) != string(signature) {
		t.Error("Signature mismatch")
	}
}

func TestSimpleCertificate_MarshalUnmarshalJSON(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	issuerPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate issuer key pair: %v", err)
	}

	signature := ed25519.Sign(privKey, pubKey)
	originalCert := NewSimpleCertificate("test", pubKey, issuerPubKey, signature)

	// Test MarshalJSON
	jsonData, err := json.Marshal(originalCert)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}

	// Test UnmarshalJSON
	var unmarshaled SimpleCertificate
	err = json.Unmarshal(jsonData, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal certificate: %v", err)
	}

	if !unmarshaled.PublicKey().Equal(originalCert.PublicKey()) {
		t.Error("Public key mismatch after JSON round trip")
	}
	// Verify that the unmarshaled certificate matches the original
	if !unmarshaled.PublicKey().Equal(originalCert.PublicKey()) {
		t.Error("Public key mismatch after JSON round trip")
	}
	if !unmarshaled.IssuerPublicKey().Equal(originalCert.IssuerPublicKey()) {
		t.Error("Issuer public key mismatch after JSON round trip")
	}
	if string(unmarshaled.Signature()) != string(originalCert.Signature()) {
		t.Error("Signature mismatch after JSON round trip")
	}
}

func TestIssueCertificate(t *testing.T) {
	// Create issuer signer
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	issuerSigner := NewEd25519Signer(pubKey, privateKey)

	// Create subject key pair
	subjectPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate subject key pair: %v", err)
	}

	// Issue certificate
	cert, err := IssueCertificate("test", subjectPubKey, issuerSigner)
	if err != nil {
		t.Fatalf("Failed to issue certificate: %v", err)
	}

	// Verify certificate properties
	if !cert.PublicKey().Equal(subjectPubKey) {
		t.Error("Certificate public key doesn't match subject public key")
	}
	if !cert.IssuerPublicKey().Equal(issuerSigner.PublicKey()) {
		t.Error("Certificate issuer public key doesn't match issuer signer public key")
	}

	// Verify signature
	if !VerifySignature(cert.IssuerPublicKey(), cert.PublicKey(), cert.Signature()) {
		t.Error("Certificate signature is invalid")
	}
}

func TestIssueCertificate_NilInputs(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	issuerSigner := NewEd25519Signer(pubKey, privateKey)

	_, err = IssueCertificate("test", nil, issuerSigner)
	if err == nil {
		t.Error("Expected error for nil subject public key")
	}

	// Test with nil issuer
	subjectPubKey, _, _ := ed25519.GenerateKey(nil)
	_, err = IssueCertificate("test", subjectPubKey, nil)
	if err == nil {
		t.Error("Expected error for nil issuer")
	}
}

func TestCreateRootCertificate(t *testing.T) {
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

	// Verify root certificate is self-signed
	if !rootCert.PublicKey().Equal(rootSigner.PublicKey()) {
		t.Error("Root certificate public key doesn't match signer public key")
	}
	if !rootCert.IssuerPublicKey().Equal(rootSigner.PublicKey()) {
		t.Error("Root certificate issuer public key doesn't match signer public key")
	}

	// Verify signature
	if !VerifySignature(rootCert.IssuerPublicKey(), rootCert.PublicKey(), rootCert.Signature()) {
		t.Error("Root certificate signature is invalid")
	}
}

func TestCreateRootCertificate_NilSigner(t *testing.T) {
	_, err := CreateRootCertificate("test", nil)
	if err == nil {
		t.Error("Expected error for nil root signer")
	}
}

func TestSimpleCertificate_JSONFormat(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	issuerPubKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate issuer key pair: %v", err)
	}

	signature := ed25519.Sign(privKey, pubKey)
	cert := NewSimpleCertificate("test", pubKey, issuerPubKey, signature)

	jsonData, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("Failed to marshal certificate: %v", err)
	}

	// Parse the JSON to verify format
	var jsonStruct struct {
		PublicKey       string `json:"publicKey"`
		Signature       string `json:"signature"`
		IssuerPublicKey string `json:"issuerPublicKey"`
	}

	err = json.Unmarshal(jsonData, &jsonStruct)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Verify hex encoding
	expectedPubKey := hex.EncodeToString(pubKey)
	expectedIssuerPubKey := hex.EncodeToString(issuerPubKey)
	expectedSignature := hex.EncodeToString(signature)

	if jsonStruct.PublicKey != expectedPubKey {
		t.Error("Public key hex encoding mismatch")
	}
	if jsonStruct.IssuerPublicKey != expectedIssuerPubKey {
		t.Error("Issuer public key hex encoding mismatch")
	}
	if jsonStruct.Signature != expectedSignature {
		t.Error("Signature hex encoding mismatch")
	}
}
