package certification

import (
	"crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	cert := NewSimpleCertificate(pubKey, issuerPubKey, "test", signature)

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

func TestIssueCertificateAndVerify(t *testing.T) {
	_, issuerPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to create issuer key pair")
	issuerSigner := NewEd25519Signer(issuerPrivKey, "github:issuer.keys")

	subjectPubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate subject key pair")

	cert, err := IssueCertificate(subjectPubKey, issuerSigner)
	require.NoError(t, err, "Failed to issue certificate")
	require.NotNil(t, cert)

	assert.True(t, cert.PublicKey().Equal(subjectPubKey))
	assert.True(t, cert.IssuerPublicKey().Equal(issuerSigner.PublicKey()))
	assert.Equal(t, "github:issuer.keys", cert.IssuerReference())
	assert.NotEmpty(t, cert.Signature())

	// 5. Verify Signature using the built-in method
	assert.True(t, cert.Verify(), "Certificate signature should be valid")
}

func TestVerify_TamperedCertificate(t *testing.T) {
	_, issuerPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	issuerSigner := NewEd25519Signer(issuerPrivKey, "github:issuer.keys")
	subjectPubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	cert, err := IssueCertificate(subjectPubKey, issuerSigner)
	require.NoError(t, err)
	require.True(t, cert.Verify(), "Freshly issued certificate should be valid")

	t.Run("Tamper IssuerRef", func(t *testing.T) {
		tamperedCert := *cert
		tamperedCert.IssuerRef = "tampered:ref"
		assert.False(t, tamperedCert.Verify(), "Signature should be invalid after tampering with IssuerRef")
	})

	t.Run("Tamper SubjectPubKey", func(t *testing.T) {
		tamperedCert := *cert
		tamperedPubKey, _, _ := ed25519.GenerateKey(nil)
		tamperedCert.PubKey = tamperedPubKey
		assert.False(t, tamperedCert.Verify(), "Signature should be invalid after tampering with SubjectPubKey")
	})

	t.Run("Tamper IssuerPubKey", func(t *testing.T) {
		tamperedCert := *cert
		tamperedIssuerKey, _, _ := ed25519.GenerateKey(nil)
		tamperedCert.IssuerPubKey = tamperedIssuerKey
		assert.False(t, tamperedCert.Verify(), "Signature should be invalid after tampering with IssuerPubKey")
	})
}

func TestVerify_NilFields(t *testing.T) {
	cert := &SimpleCertificate{}
	assert.False(t, cert.Verify(), "Verification should fail safely with nil fields")

	_, issuerPrivKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	issuerSigner := NewEd25519Signer(issuerPrivKey, "ref")
	subjectPubKey, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	cert, err = IssueCertificate(subjectPubKey, issuerSigner)
	require.NoError(t, err)

	cert.Sig = []byte{}
	assert.False(t, cert.Verify(), "Verification should fail with nil signature")
}
