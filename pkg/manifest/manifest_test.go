package manifest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTestCertificate(t *testing.T) Certificate {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	signature := ed25519.Sign(privKey, pubKey)

	return &SimpleCertificate{
		PubKey:       pubKey,
		Sig:          signature,
		IssuerPubKey: pubKey, // Self-signed for testing
	}
}

func TestNew(t *testing.T) {
	entities := []Entity{
		{Name: "file1.txt", Checksum: "abc123", IsDir: false},
		{Name: "dir1", Checksum: "", IsDir: true},
	}

	manifest := New(entities)

	if manifest == nil {
		t.Fatal("New() returned nil")
	}
	if len(manifest.Entities) != 2 {
		t.Errorf("Expected 2 entities, got %d", len(manifest.Entities))
	}
	if manifest.Entities[0].Name != "file1.txt" {
		t.Errorf("Expected first entity name 'file1.txt', got '%s'", manifest.Entities[0].Name)
	}
	if manifest.HMAC != "" {
		t.Error("HMAC should be empty for new manifest")
	}
	if manifest.Auditor != nil {
		t.Error("Auditor should be nil for new manifest")
	}
}

func TestSimpleCertificate_Interface(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	signature := ed25519.Sign(privKey, pubKey)
	cert := &SimpleCertificate{
		PubKey:       pubKey,
		Sig:          signature,
		IssuerPubKey: pubKey,
	}

	// Test interface compliance
	var _ Certificate = cert

	// Test methods
	if !cert.PublicKey().Equal(pubKey) {
		t.Error("PublicKey() method failed")
	}
	if string(cert.Signature()) != string(signature) {
		t.Error("Signature() method failed")
	}
	if !cert.IssuerPublicKey().Equal(pubKey) {
		t.Error("IssuerPublicKey() method failed")
	}
}

func TestManifest_SetAuditedBy(t *testing.T) {
	manifest := New([]Entity{
		{Name: "test.txt", Checksum: "abc123", IsDir: false},
	})

	cert := createTestCertificate(t)
	manifestSignature := []byte("test-signature")

	beforeTime := time.Now()
	manifest.SetAuditedBy(cert, manifestSignature)
	afterTime := time.Now()

	if manifest.Auditor == nil {
		t.Fatal("Auditor should not be nil after SetAuditedBy")
	}

	// Check timestamp is reasonable
	if manifest.Auditor.Timestamp.Before(beforeTime) || manifest.Auditor.Timestamp.After(afterTime) {
		t.Error("Auditor timestamp is not within expected range")
	}

	// Check certificate data
	expectedPubKey := hex.EncodeToString(cert.PublicKey())
	if manifest.Auditor.Certificate.PublicKey != expectedPubKey {
		t.Errorf("Expected public key %s, got %s", expectedPubKey, manifest.Auditor.Certificate.PublicKey)
	}

	expectedSig := hex.EncodeToString(cert.Signature())
	if manifest.Auditor.Certificate.Signature != expectedSig {
		t.Errorf("Expected signature %s, got %s", expectedSig, manifest.Auditor.Certificate.Signature)
	}

	expectedIssuerPubKey := hex.EncodeToString(cert.IssuerPublicKey())
	if manifest.Auditor.Certificate.IssuerPublicKey != expectedIssuerPubKey {
		t.Errorf("Expected issuer public key %s, got %s", expectedIssuerPubKey, manifest.Auditor.Certificate.IssuerPublicKey)
	}

	// Check manifest signature
	expectedManifestSig := hex.EncodeToString(manifestSignature)
	if manifest.Auditor.ManifestSignature != expectedManifestSig {
		t.Errorf("Expected manifest signature %s, got %s", expectedManifestSig, manifest.Auditor.ManifestSignature)
	}
}

func TestManifest_GetAuditorCertificate(t *testing.T) {
	manifest := New([]Entity{})

	// Test with no auditor
	cert := manifest.GetAuditorCertificate()
	if cert != nil {
		t.Error("GetAuditorCertificate should return nil when no auditor is set")
	}

	// Set auditor and test
	originalCert := createTestCertificate(t)
	manifest.SetAuditedBy(originalCert, []byte("test-sig"))

	retrievedCert := manifest.GetAuditorCertificate()
	if retrievedCert == nil {
		t.Fatal("GetAuditorCertificate should not return nil when auditor is set")
	}

	// Compare certificate data
	if !retrievedCert.PublicKey().Equal(originalCert.PublicKey()) {
		t.Error("Retrieved certificate public key doesn't match original")
	}
	if string(retrievedCert.Signature()) != string(originalCert.Signature()) {
		t.Error("Retrieved certificate signature doesn't match original")
	}
	if !retrievedCert.IssuerPublicKey().Equal(originalCert.IssuerPublicKey()) {
		t.Error("Retrieved certificate issuer public key doesn't match original")
	}
}

func TestManifest_GetAuditorManifestSignature(t *testing.T) {
	manifest := New([]Entity{})

	// Test with no auditor
	sig := manifest.GetAuditorManifestSignature()
	if sig != nil {
		t.Error("GetAuditorManifestSignature should return nil when no auditor is set")
	}

	// Set auditor and test
	cert := createTestCertificate(t)
	originalSig := []byte("test-manifest-signature")
	manifest.SetAuditedBy(cert, originalSig)

	retrievedSig := manifest.GetAuditorManifestSignature()
	if string(retrievedSig) != string(originalSig) {
		t.Error("Retrieved manifest signature doesn't match original")
	}
}

func TestManifest_CalculateHMAC(t *testing.T) {
	entities := []Entity{
		{Name: "file1.txt", Checksum: "abc123", IsDir: false},
		{Name: "file2.txt", Checksum: "def456", IsDir: false},
	}
	manifest := New(entities)

	err := manifest.calculateHMAC()
	if err != nil {
		t.Fatalf("calculateHMAC failed: %v", err)
	}

	if manifest.HMAC == "" {
		t.Error("HMAC should not be empty after calculation")
	}

	// Test consistency - calculating again should give same result
	originalHMAC := manifest.HMAC
	err = manifest.calculateHMAC()
	if err != nil {
		t.Fatalf("Second calculateHMAC failed: %v", err)
	}

	if manifest.HMAC != originalHMAC {
		t.Error("HMAC should be consistent across multiple calculations")
	}
}

func TestManifest_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "test.manifest")

	// Create manifest
	entities := []Entity{
		{Name: "file1.txt", Checksum: "abc123", IsDir: false},
		{Name: "dir1", Checksum: "", IsDir: true},
	}
	originalManifest := New(entities)

	// Add auditor
	cert := createTestCertificate(t)
	manifestSignature := []byte("test-signature")
	originalManifest.SetAuditedBy(cert, manifestSignature)

	// Save manifest
	err := originalManifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("Manifest file was not created")
	}

	// Load manifest
	loadedManifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("Failed to load manifest: %v", err)
	}

	if loadedManifest == nil {
		t.Fatal("Loaded manifest is nil")
	}

	// Compare entities
	if len(loadedManifest.Entities) != len(originalManifest.Entities) {
		t.Errorf("Entity count mismatch: expected %d, got %d",
			len(originalManifest.Entities), len(loadedManifest.Entities))
	}

	for i, entity := range loadedManifest.Entities {
		original := originalManifest.Entities[i]
		if entity.Name != original.Name || entity.Checksum != original.Checksum || entity.IsDir != original.IsDir {
			t.Errorf("Entity %d mismatch: expected %+v, got %+v", i, original, entity)
		}
	}

	// Compare HMAC
	if loadedManifest.HMAC != originalManifest.HMAC {
		t.Error("HMAC mismatch between original and loaded manifest")
	}

	// Compare auditor
	if loadedManifest.Auditor == nil {
		t.Fatal("Loaded manifest auditor is nil")
	}

	if loadedManifest.Auditor.Certificate.PublicKey != originalManifest.Auditor.Certificate.PublicKey {
		t.Error("Auditor certificate public key mismatch")
	}
}

func TestManifest_LoadNonExistent(t *testing.T) {
	nonExistentPath := "/path/that/does/not/exist"

	manifest, err := LoadManifest(nonExistentPath)
	if err != nil {
		t.Errorf("Expected no error for non-existent file, got: %v", err)
	}
	if manifest != nil {
		t.Error("Expected nil manifest for non-existent file")
	}
}

func TestManifest_LoadInvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "invalid.manifest")

	// Write invalid JSON
	err := os.WriteFile(manifestPath, []byte("invalid json content"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid manifest: %v", err)
	}

	_, err = LoadManifest(manifestPath)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestManifest_LoadInvalidHMAC(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "invalid_hmac.manifest")

	// Create manifest with invalid HMAC
	invalidManifest := map[string]interface{}{
		"entities": []map[string]interface{}{
			{"name": "test.txt", "checksum": "abc123", "isDir": false},
		},
		"hmac": "invalid_hmac",
	}

	jsonData, _ := json.Marshal(invalidManifest)
	err := os.WriteFile(manifestPath, jsonData, 0644)
	if err != nil {
		t.Fatalf("Failed to write manifest with invalid HMAC: %v", err)
	}

	_, err = LoadManifest(manifestPath)
	if err == nil {
		t.Error("Expected error for invalid HMAC")
	}
	if err != nil && err.Error() != "invalid HMAC" {
		t.Errorf("Expected 'invalid HMAC' error, got: %v", err)
	}
}

func TestManifest_Touch(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "test.manifest")

	// Create and save manifest
	manifest := New([]Entity{{Name: "test.txt", Checksum: "abc123", IsDir: false}})
	err := manifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Get initial modification time
	info1, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatalf("Failed to stat manifest file: %v", err)
	}
	initialModTime := info1.ModTime()

	// Sleep to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Touch the file
	err = manifest.Touch(manifestPath)
	if err != nil {
		t.Fatalf("Failed to touch manifest: %v", err)
	}

	// Get new modification time
	info2, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatalf("Failed to stat manifest file after touch: %v", err)
	}
	newModTime := info2.ModTime()

	if !newModTime.After(initialModTime) {
		t.Error("Modification time should be updated after touch")
	}
}

func TestGetModTime(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "test.manifest")

	// Test non-existent file
	_, err := GetModTime(manifestPath)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Create file and test
	manifest := New([]Entity{})
	err = manifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	modTime, err := GetModTime(manifestPath)
	if err != nil {
		t.Fatalf("Failed to get mod time: %v", err)
	}

	// Verify it's a reasonable time (within last minute)
	if time.Since(modTime) > time.Minute {
		t.Error("Modification time seems too old")
	}
}

func TestLoadManifestIfFresh(t *testing.T) {
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "test.manifest")

	// Test with nil freshness limit
	manifest, err := LoadManifestIfFresh(manifestPath, nil)
	if err != nil {
		t.Errorf("Unexpected error with nil freshness limit: %v", err)
	}
	if manifest != nil {
		t.Error("Expected nil manifest with nil freshness limit")
	}

	// Create and save manifest
	originalManifest := New([]Entity{{Name: "test.txt", Checksum: "abc123", IsDir: false}})
	err = originalManifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Test with fresh manifest
	freshnessLimit := 1 * time.Hour
	manifest, err = LoadManifestIfFresh(manifestPath, &freshnessLimit)
	if err != nil {
		t.Fatalf("Failed to load fresh manifest: %v", err)
	}
	if manifest == nil {
		t.Error("Expected non-nil manifest for fresh file")
	}

	// Make file stale by setting old timestamp
	staleTime := time.Now().Add(-2 * time.Hour)
	err = os.Chtimes(manifestPath, staleTime, staleTime)
	if err != nil {
		t.Fatalf("Failed to make file stale: %v", err)
	}

	// Test with stale manifest
	shortFreshnessLimit := 30 * time.Minute
	manifest, err = LoadManifestIfFresh(manifestPath, &shortFreshnessLimit)
	if err != nil {
		t.Errorf("Unexpected error with stale manifest: %v", err)
	}
	if manifest != nil {
		t.Error("Expected nil manifest for stale file")
	}

	// Test with non-existent file
	nonExistentPath := filepath.Join(tempDir, "nonexistent.manifest")
	manifest, err = LoadManifestIfFresh(nonExistentPath, &freshnessLimit)
	if err != nil {
		t.Errorf("Unexpected error for non-existent file: %v", err)
	}
	if manifest != nil {
		t.Error("Expected nil manifest for non-existent file")
	}
}

func TestManifest_DataWithoutAuditor(t *testing.T) {
	// Create manifest with auditor
	manifest := New([]Entity{{Name: "test.txt", Checksum: "abc123", IsDir: false}})
	cert := createTestCertificate(t)
	manifest.SetAuditedBy(cert, []byte("test-signature"))

	// Get data without auditor
	data, err := manifest.DataWithoutAuditor()
	if err != nil {
		t.Fatalf("Failed to get data without auditor: %v", err)
	}

	// Parse the JSON to verify auditor is not included
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if _, exists := result["auditor"]; exists {
		t.Error("Auditor should not be present in data without auditor")
	}

	// Verify entities are still present
	entities, exists := result["entities"]
	if !exists {
		t.Error("Entities should be present in data without auditor")
	}

	entitiesSlice, ok := entities.([]interface{})
	if !ok || len(entitiesSlice) != 1 {
		t.Error("Expected one entity in data without auditor")
	}
}

func TestManifest_JSONSerialization(t *testing.T) {
	// Create manifest with all fields populated
	entities := []Entity{
		{Name: "file1.txt", Checksum: "abc123", IsDir: false},
		{Name: "dir1", Checksum: "", IsDir: true},
	}
	manifest := New(entities)
	cert := createTestCertificate(t)
	manifestSignature := []byte("test-signature")
	manifest.SetAuditedBy(cert, manifestSignature)

	// Marshal to JSON
	jsonData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Failed to marshal manifest: %v", err)
	}

	// Unmarshal back
	var unmarshaledManifest Manifest
	err = json.Unmarshal(jsonData, &unmarshaledManifest)
	if err != nil {
		t.Fatalf("Failed to unmarshal manifest: %v", err)
	}

	// Compare entities
	if len(unmarshaledManifest.Entities) != len(manifest.Entities) {
		t.Error("Entity count mismatch after JSON round trip")
	}

	// Compare auditor
	if unmarshaledManifest.Auditor == nil {
		t.Error("Auditor should not be nil after JSON round trip")
	}

	if unmarshaledManifest.Auditor.Certificate.PublicKey != manifest.Auditor.Certificate.PublicKey {
		t.Error("Auditor certificate public key mismatch after JSON round trip")
	}
}

func TestManifest_EmptyEntities(t *testing.T) {
	manifest := New([]Entity{})

	// Test save/load with empty entities
	tempDir := t.TempDir()
	manifestPath := filepath.Join(tempDir, "empty.manifest")

	err := manifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save empty manifest: %v", err)
	}

	loadedManifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("Failed to load empty manifest: %v", err)
	}

	if len(loadedManifest.Entities) != 0 {
		t.Error("Expected empty entities list")
	}
}

func TestCertificateData_HexEncoding(t *testing.T) {
	// Test that hex encoding/decoding works correctly
	cert := createTestCertificate(t)
	manifest := New([]Entity{})
	manifest.SetAuditedBy(cert, []byte{0xDE, 0xAD, 0xBE, 0xEF})

	// Check that the hex values are correct
	expectedPubKeyHex := hex.EncodeToString(cert.PublicKey())
	if manifest.Auditor.Certificate.PublicKey != expectedPubKeyHex {
		t.Error("Public key hex encoding mismatch")
	}

	expectedSigHex := hex.EncodeToString(cert.Signature())
	if manifest.Auditor.Certificate.Signature != expectedSigHex {
		t.Error("Signature hex encoding mismatch")
	}

	expectedManifestSigHex := hex.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if manifest.Auditor.ManifestSignature != expectedManifestSigHex {
		t.Error("Manifest signature hex encoding mismatch")
	}

	// Test decoding
	retrievedCert := manifest.GetAuditorCertificate()
	if !retrievedCert.PublicKey().Equal(cert.PublicKey()) {
		t.Error("Public key hex decoding mismatch")
	}

	retrievedManifestSig := manifest.GetAuditorManifestSignature()
	expectedBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if string(retrievedManifestSig) != string(expectedBytes) {
		t.Error("Manifest signature hex decoding mismatch")
	}
}
