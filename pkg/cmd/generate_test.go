package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/certification"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGenerateCmd(t *testing.T) {
	cmd := NewGenerateCmd()

	// Test command properties
	assert.Equal(t, "generate [directory]", cmd.Use)
	assert.Equal(t, "Generate and write manifest files recursively", cmd.Short)
	assert.Contains(t, cmd.Long, "Generate and write manifest files recursively")
	assert.Error(t, cmd.Args(cmd, []string{"arg1", "arg2"})) // Too many args
	assert.True(t, cmd.SilenceUsage)
}

func TestGenerateCmd_NoArguments(t *testing.T) {
	t.Skip()
	// Create temporary directory structure
	tempDir := t.TempDir()

	// Create test files
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	// Change to temp directory so "." refers to it
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.Chdir(oldWd))
	}()
	require.NoError(t, os.Chdir(tempDir))

	cmd := NewGenerateCmd()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{})
	require.NoError(t, err)

	// Verify manifest was created
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	assert.FileExists(t, manifestPath)

	assert.Contains(t, output, "processed")
	assert.Contains(t, output, "directory")
}

func TestGenerateCmd_WithDirectoryStructure(t *testing.T) {

	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt":       "test content",
		"subdir/sub.txt": "sub content",
	})

	cmd := NewGenerateCmd()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})
	require.NoError(t, err)

	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	assert.FileExists(t, manifestPath)

	subManifestPath := filepath.Join(tempDir, "subdir", ".bytecheck.manifest")
	assert.FileExists(t, subManifestPath)

	assert.Contains(t, output, "processed 2 directory(s) (0 cached)")
}

func TestGenerateCmd_NonExistentDirectory(t *testing.T) {
	nonExistentDir := "/path/that/does/not/exist"
	_, err := ExecuteCommandWithCapture(t, NewGenerateCmd(), []string{nonExistentDir})
	assert.Error(t, err)
}

func TestGenerateCmd_WithoutFreshnessLimit_MustRegenerateManifest(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{"test.txt": "test content"})

	CreateFreshManifest(t, tempDir)

	cmd := NewGenerateCmd()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})
	require.NoError(t, err)

	assert.Contains(t, output, "processed 1 directory(s) (0 cached)")
}

func TestGenerateCmd_WithLongFreshnessLimitManifest(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{"test.txt": "test content"})

	CreateFreshManifest(t, tempDir)

	cmd := NewGenerateCmd()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--freshness-interval", "1h"})
	require.NoError(t, err)

	assert.Contains(t, output, "processed 1 directory(s) (1 cached)")
}

func TestGenerateCmd_WithLongFreshnessLimitButCorruptedManifest(t *testing.T) {
	tempDir := t.TempDir()

	manifestPath := CreateFreshManifest(t, tempDir)
	err := CorruptFileByOneByte(t, manifestPath, 123)
	require.NoError(t, err)

	cmd := NewGenerateCmd()
	_, err = ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--freshness-interval", "1h"})
	require.ErrorContains(t, err, "invalid HMAC")
}

func TestGenerateCmd_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()

	// Create many files to make the operation take some time
	for i := 0; i < 100; i++ {
		testFile := filepath.Join(tempDir, fmt.Sprintf("test%d.txt", i))
		require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))
	}

	// Create command
	cmd := NewGenerateCmd()

	// Create context that will be cancelled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Set context
	cmd.SetContext(ctx)
	_, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})

	// Should get context cancellation error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestGenerateCmd_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	cmd := NewGenerateCmd()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})
	require.NoError(t, err)

	// Verify empty manifest was created
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	assert.FileExists(t, manifestPath)

	assert.Contains(t, output, "processed")
}

func TestGenerateCmd_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping permission test when running as root")
	}

	tempDir := t.TempDir()
	restrictedDir := filepath.Join(tempDir, "restricted")
	require.NoError(t, os.MkdirAll(restrictedDir, 0755))

	// Create a file in the restricted directory
	testFile := filepath.Join(restrictedDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	// Remove read permissions from the directory
	require.NoError(t, os.Chmod(restrictedDir, 0000))
	defer os.Chmod(restrictedDir, 0755) // Restore permissions for cleanup

	cmd := NewGenerateCmd()
	_, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})
	assert.Error(t, err)
}

func TestGenerateCmd_LargeStructure1(t *testing.T) {
	structure := SampleStructure{
		Files: []SampleFile{
			{
				Path:     "recent_file.txt",
				Content:  "This file was modified recently",
				Modified: -5 * time.Minute, // 5 minutes ago
			},
			{
				Path:     "old_file.txt",
				Content:  "This file is old",
				Modified: -2 * 24 * time.Hour, // 2 days ago
			},
			{
				Path:     "future_file.txt", // Future timestamp (rare but possible)
				Content:  "This file has future timestamp",
				Modified: 1 * time.Hour, // 1 hour in future
			},
			{
				Path: "sub1/test1.txt",
			},
			{
				Path: "sub2/test2.txt",
			},
			{
				Path:     "sub2/sub2_sub/test3.txt",
				Modified: -2 * 24 * time.Hour, // 2 days ago
			},
		},
		Dirs: []SampleDir{
			{Path: "sub1"},
			{Path: "sub2"},
			{Path: "sub2/sub2_sub"},
			{Path: "sub3_empty"},
		},
	}
	tempDir := CreateSampleStructure(t, structure)

	cmd := NewGenerateCmd()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})
	require.NoError(t, err)

	expectedManifests := []string{
		filepath.Join(tempDir, ".bytecheck.manifest"),
		filepath.Join(tempDir, "sub1", ".bytecheck.manifest"),
		filepath.Join(tempDir, "sub2", ".bytecheck.manifest"),
		filepath.Join(tempDir, "sub3_empty", ".bytecheck.manifest"),
		filepath.Join(tempDir, "sub2", "sub2_sub", ".bytecheck.manifest"),
	}

	for _, manifest := range expectedManifests {
		assert.FileExists(t, manifest, "Expected manifest: %s", manifest)
	}

	assert.Contains(t, output, "processed 5 directory(s) (0 cached)")

	cmd = NewGenerateCmd()
	output, err = ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--freshness-interval", "1h"})
	require.NoError(t, err)

	assert.Contains(t, output, "processed 5 directory(s) (5 cached)")

	cmd = NewGenerateCmd()
	output, err = ExecuteCommandWithCapture(t, cmd, []string{tempDir})
	require.NoError(t, err)

	assert.Contains(t, output, "processed 5 directory(s) (0 cached)")
}

func TestGenerateCmd_WithDirectoryStructureAndPrivateKeyWithoutIssuerReference_mustReturnError(t *testing.T) {

	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt":       "test content",
		"subdir/sub.txt": "sub content",
	})

	cmd := NewGenerateCmd()
	_, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--private-key", "test.key"})
	require.Error(t, err)
	require.ErrorContains(t, err, "issuer reference is required when using private key")
}

func TestGenerateCmd_WithPrivateKeyAndIssuerReference_mustSignManifestWithAuditorSection(t *testing.T) {

	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt": "test content",
	})
	testPrivateKey := filepath.Join(tempDir, "test.key")
	privateKey, _, err := certification.GenerateKeyPair(testPrivateKey, testPrivateKey+".pub")
	require.NoError(t, err)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	cmd := NewGenerateCmd()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--private-key", filepath.Join(tempDir, "test.key"), "--auditor-reference", "github:test-issuer"})
	require.NoError(t, err)

	assert.Contains(t, output, "processed 1 directory(s) (0 cached)")

	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	m, err := manifest.LoadManifest(manifestPath)
	require.NoError(t, err)
	assert.NotNil(t, m.Auditor)
	assert.Equal(t, m.Auditor.Certificate.IssuerPublicKey, hex.EncodeToString(publicKey))
}
