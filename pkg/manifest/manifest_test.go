package manifest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate is a helper function to create a new Certificate for testing.
func createTestCertificate(t *testing.T) Certificate {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err, "Failed to generate key pair")

	signature := ed25519.Sign(privKey, pubKey)

	return &SimpleCertificate{
		PubKey:       pubKey,
		Sig:          signature,
		IssuerPubKey: pubKey, // Self-signed for testing
		IssuerRef:    "test-issuer",
	}
}

func TestNew(t *testing.T) {
	entities := []Entity{
		{Name: "file2.txt", Checksum: "def456"},
		{Name: "file1.txt", Checksum: "abc123"},
	}

	manifest := New(entities)
	require.NotNil(t, manifest)
	assert.Len(t, manifest.Entities, 2)
	// Verify that New() sorts the entities by name
	assert.Equal(t, "file1.txt", manifest.Entities[0].Name)
	assert.Equal(t, "file2.txt", manifest.Entities[1].Name)
	assert.Empty(t, manifest.HMAC, "HMAC should be empty for a new manifest")
	assert.Nil(t, manifest.Auditor, "Auditor should be nil for a new manifest")
}

func TestSimpleCertificate_Interface(t *testing.T) {
	cert := createTestCertificate(t)
	require.NotNil(t, cert)

	assert.Implements(t, (*Certificate)(nil), cert)

	simpleCert, ok := cert.(*SimpleCertificate)
	require.True(t, ok)

	assert.True(t, cert.PublicKey().Equal(simpleCert.PubKey))
	assert.Equal(t, simpleCert.Sig, cert.Signature())
	assert.True(t, cert.IssuerPublicKey().Equal(simpleCert.IssuerPubKey))
	assert.Equal(t, "test-issuer", cert.IssuerReference())
}

func TestManifest_AuditorFlow(t *testing.T) {
	manifest := New([]Entity{{Name: "test.txt", Checksum: "abc123"}})

	// 1. Test with no auditor
	assert.Nil(t, manifest.GetAuditorCertificate())
	assert.Nil(t, manifest.GetAuditorManifestSignature())

	// 2. Set the auditor
	cert := createTestCertificate(t)
	manifestSignature := []byte("test-signature")
	beforeTime := time.Now()
	manifest.SetAuditedBy(cert, manifestSignature)
	afterTime := time.Now()

	// 3. Verify Auditor field
	auditor := manifest.Auditor
	require.NotNil(t, auditor)
	assert.WithinDuration(t, beforeTime, auditor.Timestamp, afterTime.Sub(beforeTime))
	assert.Equal(t, hex.EncodeToString(manifestSignature), auditor.ManifestSignature)

	// 4. Verify CertificateData within Auditor
	certData := auditor.Certificate
	assert.Equal(t, hex.EncodeToString(cert.PublicKey()), certData.PublicKey)
	assert.Equal(t, hex.EncodeToString(cert.Signature()), certData.Signature)
	assert.Equal(t, hex.EncodeToString(cert.IssuerPublicKey()), certData.IssuerPublicKey)
	assert.Equal(t, cert.IssuerReference(), certData.IssuerRef)

	// 5. Verify GetAuditorCertificate
	retrievedCert := manifest.GetAuditorCertificate()
	require.NotNil(t, retrievedCert)
	assert.True(t, retrievedCert.PublicKey().Equal(cert.PublicKey()))
	assert.Equal(t, cert.Signature(), retrievedCert.Signature())
	assert.True(t, retrievedCert.IssuerPublicKey().Equal(cert.IssuerPublicKey()))
	assert.Equal(t, cert.IssuerReference(), retrievedCert.IssuerReference())

	// 6. Verify GetAuditorManifestSignature
	retrievedSig := manifest.GetAuditorManifestSignature()
	assert.Equal(t, manifestSignature, retrievedSig)

	// 7. Unset the auditor
	manifest.SetAuditedBy(nil, nil)
	assert.Nil(t, manifest.Auditor)
}

func TestManifest_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, DefaultName)

	manifest := New([]Entity{{Name: "file.txt", Checksum: "checksum123"}})
	cert := createTestCertificate(t)
	manifest.SetAuditedBy(cert, []byte("sig"))

	// Save the manifest
	err := manifest.Save(manifestPath)
	require.NoError(t, err)
	assert.FileExists(t, manifestPath)
	originalHMAC := manifest.HMAC
	assert.NotEmpty(t, originalHMAC)

	// Load the manifest
	loadedManifest, err := LoadManifest(manifestPath)
	require.NoError(t, err)
	require.NotNil(t, loadedManifest)

	// Verify loaded content matches original
	assert.Equal(t, originalHMAC, loadedManifest.HMAC)
	assert.Equal(t, manifest.Entities, loadedManifest.Entities)
	require.NotNil(t, loadedManifest.Auditor)
	assert.Equal(t, manifest.Auditor.Timestamp.Unix(), loadedManifest.Auditor.Timestamp.Unix())
	assert.Equal(t, manifest.Auditor.ManifestSignature, loadedManifest.Auditor.ManifestSignature)

	loadedCert := loadedManifest.GetAuditorCertificate()
	require.NotNil(t, loadedCert)
	assert.True(t, cert.PublicKey().Equal(loadedCert.PublicKey()))
}

func TestLoadManifest_InvalidHMAC(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, DefaultName)

	manifest := New([]Entity{{Name: "f"}})
	err := manifest.calculateHMAC()
	require.NoError(t, err)
	manifest.HMAC = "invalid-hmac-signature" // Set a bad HMAC
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	err = os.WriteFile(manifestPath, data, 0644)
	require.NoError(t, err)

	_, err = LoadManifest(manifestPath)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "invalid HMAC")
}

func TestLoadManifest_NotExist(t *testing.T) {
	m, err := LoadManifest(filepath.Join(t.TempDir(), "non-existent-manifest"))
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestManifest_DataWithoutAuditor(t *testing.T) {
	manifest := New([]Entity{{Name: "f"}})
	manifest.SetAuditedBy(createTestCertificate(t), []byte("sig"))

	data, err := manifest.DataWithoutAuditor()
	require.NoError(t, err)

	var untyped map[string]interface{}
	err = json.Unmarshal(data, &untyped)
	require.NoError(t, err)

	assert.NotNil(t, untyped["hmac"])
	assert.NotNil(t, untyped["entities"])
	_, hasAuditor := untyped["auditor"]
	assert.False(t, hasAuditor)
}

func TestLoadManifestIfFresh(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, DefaultName)

	err := New(nil).Save(manifestPath)
	require.NoError(t, err)

	// Test with a freshness limit that is met (manifest is fresh)
	limit := time.Hour
	freshManifest, err := LoadManifestIfFresh(manifestPath, &limit)
	require.NoError(t, err)
	require.NotNil(t, freshManifest)

	// Make the manifest file seem old
	oldTime := time.Now().Add(-2 * time.Hour)
	err = os.Chtimes(manifestPath, oldTime, oldTime)
	require.NoError(t, err)

	// Test with a freshness limit that is not met (manifest is stale)
	staleManifest, err := LoadManifestIfFresh(manifestPath, &limit)
	require.NoError(t, err)
	assert.Nil(t, staleManifest)

	// Test with a nil limit, which should always return nil
	nilLimitManifest, err := LoadManifestIfFresh(manifestPath, nil)
	require.NoError(t, err)
	assert.Nil(t, nilLimitManifest)
}
