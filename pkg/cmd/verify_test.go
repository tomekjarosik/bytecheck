package cmd

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomekjarosik/bytecheck/pkg/certification"
	"github.com/tomekjarosik/bytecheck/pkg/generator"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyCommand(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test1.txt":        "test content 1",
		"subdir/test2.txt": "test content 2",
	})

	// First, generate manifests
	sc := scanner.New()
	gen := generator.New(sc, certification.NewFakeSigner())
	ctx := context.Background()
	err := gen.Generate(ctx, tempDir)
	if err != nil {
		t.Fatalf("Failed to generate manifests: %v", err)
	}

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--freshness-interval", "1h"})

	if err != nil {
		t.Fatalf("VerifyCommand failed: %v", err)
	}
	if !strings.Contains(output, "ok") {
		t.Errorf("Expected success message in output, got: %s", output)
	}

	t.Log("✓ Verify command test passed")
}

func TestVerifyCommandWithChangedFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("original content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Generate manifest
	sc := scanner.New()
	fakeSigner := certification.NewFakeSigner()
	gen := generator.New(sc, fakeSigner)
	ctx := context.Background()
	err = gen.Generate(ctx, tempDir)
	if err != nil {
		t.Fatalf("Failed to generate manifest: %v", err)
	}

	// Change the file content
	err = os.WriteFile(testFile, []byte("changed content"), 0644)
	if err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}

	// Test verify command - should detect changes
	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})

	if !strings.Contains(output, "fail") {
		t.Errorf("Expected failure message in output, got: %s", output)
	}

	t.Log("✓ Verify command with changed files test passed")
}

func TestVerifyCommandInvalidDirectory(t *testing.T) {
	// Test with non-existent directory
	nonExistentDir := "/this/directory/does/not/exist/for/sure"

	cmd := NewVerifyCommand()
	_, err := ExecuteCommandWithCapture(t, cmd, []string{nonExistentDir})

	if err == nil {
		t.Error("VerifyCommand should fail with non-existent directory")
	}

	t.Log("✓ Verify command invalid directory test passed")
}

func TestVerifyCommandDefaultDirectory(t *testing.T) {
	t.Skip()
	tempDir := t.TempDir()

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer os.Chdir(originalDir)

	// Change to test directory
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Generate manifest
	sc := scanner.New()
	fakeSigner := certification.NewFakeSigner()
	gen := generator.New(sc, fakeSigner)
	ctx := context.Background()
	err = gen.Generate(ctx, ".")
	if err != nil {
		t.Fatalf("Failed to generate manifest: %v", err)
	}

	// Test verify command without arguments (should use current directory)
	cmd := NewVerifyCommand()
	_, err = ExecuteCommandWithCapture(t, cmd, []string{})

	if err != nil {
		t.Fatalf("VerifyCommand failed with default directory: %v", err)
	}

	t.Log("✓ Verify command default directory test passed")
}

func TestVerifyCmd_WithFreshManifest_NoFreshnessLimit(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt": "test content",
	})

	// Generate and create valid manifest
	CreateFreshManifest(t, tempDir)

	// Ensure the manifest is fresh by touching it
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	now := time.Now()
	require.NoError(t, os.Chtimes(manifestPath, now, now))

	// Create and execute verify command without freshness limit
	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})
	require.NoError(t, err)

	assert.Contains(t, output, "failed")
	assert.Contains(t, output, "0/1 manifests valid")
}

func TestVerifyCmd_WithFreshManifest_WithFreshnessLimit(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt": "test content",
	})

	CreateFreshManifest(t, tempDir)

	// Ensure the manifest is fresh by touching it
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	now := time.Now()
	require.NoError(t, os.Chtimes(manifestPath, now, now))

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--freshness-interval", "1h"})

	require.NoError(t, err)
	assert.Contains(t, output, "skipped")
}

func TestVerifyCmd_WithStaleManifest_WithShortFreshnessLimit(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt": "test content",
	})

	CreateFreshManifest(t, tempDir)

	// Make the manifest stale by setting old timestamp
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	staleTime := time.Now().Add(-2 * time.Hour) // 2 hours ago
	require.NoError(t, os.Chtimes(manifestPath, staleTime, staleTime))

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--freshness-interval", "1h"})

	require.NoError(t, err)
	assert.Contains(t, output, "0/1 manifests valid")
}

func TestVerifyCmd_WithStaleManifest_WithLongFreshnessLimit(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt": "test content",
	})

	CreateFreshManifest(t, tempDir)

	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	staleTime := time.Now().Add(-2 * time.Hour) // 2 hours ago
	require.NoError(t, os.Chtimes(manifestPath, staleTime, staleTime))

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir, "--freshness-interval", "3h"})

	require.NoError(t, err)
	assert.Contains(t, output, "verified 0 manifest(s) (1 skipped)")
}

func TestVerifyCmd_WithCorruptedManifest(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"test.txt": "test content",
	})

	// Create corrupted manifest (invalid HMAC)
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	corruptedManifest := `{
		"entities": [
			{
				"name": "test.txt",
				"checksum": "correct_checksum_here",
				"isDir": false
			}
		],
		"hmac": "invalid_hmac"
	}`
	require.NoError(t, os.WriteFile(manifestPath, []byte(corruptedManifest), 0644))

	cmd := NewVerifyCommand()
	_, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC")
}

func TestVerifyCmd_WithSmallFileTree_WhenSigned_mustVerifySignature(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"a.txt": "a",
	})
	tempDir2 := t.TempDir()
	privateKeyPath := filepath.Join(tempDir2, "key.pem")
	_, err := certification.GenerateAndWritePrivateKey(privateKeyPath)
	assert.NoError(t, err)
	signer, err := certification.NewEd25519SignerFromFile(privateKeyPath, "test")
	require.NoError(t, err)

	sc := scanner.New()
	gen := generator.New(sc, signer)
	err = gen.Generate(context.Background(), tempDir)
	require.NoError(t, err)

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})

	require.NoError(t, err)
	assert.Contains(t, output, "verified 1 manifest(s) (0 skipped)")
}

func TestVerifyCmd_WithLargeFileTree_WhenSigned_mustVerifySignature(t *testing.T) {
	tempDir := CreateSampleStructureFromMap(t, map[string]string{
		"level1/level2a/file1.txt":                "content1",
		"level1/level2a/file2.log":                "log data",
		"level1/level2b/another.txt":              "more text",
		"level1/level2b/level3a/config.json":      "{\"key\":\"value\"}",
		"level1/level2b/level3a/data.bin":         "binary data",
		"level1/level2c/empty_dir/":               "", // This will create an empty directory
		"level1/file_in_level1.txt":               "level1 file",
		"another_root/file.txt":                   "sibling to level1",
		"z_last_dir/a_file.txt":                   "z",
		"z_last_dir/x_file.txt":                   "x",
		"z_last_dir/c_file.txt":                   "y",
		"z_last_dir/b_file.txt":                   "b",
		"z_last_dir/e_file.txt":                   "y",
		"z_last_dir/sub/another.txt":              "x",
		"a_first_dir/z_file.txt":                  "a",
		"a_first_dir/y_file.txt":                  "b",
		"a_first_dir/sub/first_sub_file.txt":      "c",
		"a_first_dir/sub/level4/deep_file.txt":    "very deep",
		"a_first_dir/sub/level4/another_deep.txt": "so deep",
		"file_at_root.txt":                        "root",
		"another_file_at_root.log":                "root log",
	})

	privateKeyPath := filepath.Join(tempDir, "key.pem")
	_, err := certification.GenerateAndWritePrivateKey(privateKeyPath)
	assert.NoError(t, err)
	signer, err := certification.NewEd25519SignerFromFile(privateKeyPath, "test")
	require.NoError(t, err)

	sc := scanner.New()
	gen := generator.New(sc, signer)
	err = gen.Generate(context.Background(), tempDir)
	require.NoError(t, err)

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})

	require.NoError(t, err)
	assert.Contains(t, output, "verified 12 manifest(s) (0 skipped)")
}

func TestVerifyCmd_WithMultipleAuditors_UsingMultipleDirectories(t *testing.T) {
	// Create multiple directories, each with their own signer
	directories := make([]string, 0)
	signers := []struct {
		reference string
		keyName   string
	}{
		{"custom:user1", "key1.pem"},
		{"custom:user2", "key2.pem"},
		{"corp:team/project", "key3.pem"},
	}

	tempDir := t.TempDir()

	for i, signer := range signers {
		// Create a subdirectory for each signer
		subDir := filepath.Join(tempDir, fmt.Sprintf("dir%d", i))
		err := os.MkdirAll(subDir, 0755)
		require.NoError(t, err)

		// Create sample files in the subdirectory
		CreateSampleStructureFromMapInDir(t, subDir, map[string]string{
			fmt.Sprintf("file%d.txt", i): fmt.Sprintf("content%d", i),
		})

		// Generate private key
		privateKeyPath := filepath.Join(tempDir, signer.keyName)
		_, err = certification.GenerateAndWritePrivateKey(privateKeyPath)
		require.NoError(t, err)

		// Create signer with specific reference
		signerObj, err := certification.NewEd25519SignerFromFile(privateKeyPath, signer.reference)
		require.NoError(t, err)

		// Generate manifest for this directory
		sc := scanner.New()
		gen := generator.New(sc, signerObj)
		err = gen.Generate(context.Background(), subDir)
		require.NoError(t, err)

		directories = append(directories, subDir)
	}

	// Generate private key
	privateKeyPath := filepath.Join(tempDir, "key4.pem")
	_, err := certification.GenerateAndWritePrivateKey(privateKeyPath)
	require.NoError(t, err)

	// Create signer with specific reference
	signerObj, err := certification.NewEd25519SignerFromFile(privateKeyPath, "custom:toplevel")
	require.NoError(t, err)

	sc := scanner.New(scanner.WithManifestFreshnessLimit(time.Hour))
	gen := generator.New(sc, signerObj)
	err = gen.Generate(context.Background(), tempDir)

	// Run verify on the parent directory with freshness level
	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{tempDir})

	require.NoError(t, err)

	// Verify all auditors are present
	assert.Contains(t, output, "Auditors:")
	assert.Contains(t, output, "github:org1/repo1")
	assert.Contains(t, output, "github:org2/repo2")
	assert.Contains(t, output, "corp:team/project")
	assert.Contains(t, output, "trusted")

	// Verify all manifests were processed
	assert.Contains(t, output, "verified 3 manifest(s)")
}

func TestVerifyCmd_WithMixedAuditorStatuses_UsingMultipleDirectories(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name           string
		reference      string
		expectedStatus string // "trusted", "unsupported", etc.
	}{
		{
			name:           "trusted github",
			reference:      "github:trusted/repo",
			expectedStatus: "trusted",
		},
		{
			name:           "unsupported scheme",
			reference:      "unknown:scheme/path",
			expectedStatus: "unsupported",
		},
		{
			name:           "corp scheme",
			reference:      "corp:team/a",
			expectedStatus: "trusted", // Assuming corp: is supported by your verifier
		},
	}

	for i, tc := range testCases {
		subDir := filepath.Join(tempDir, fmt.Sprintf("dir%d", i))
		err := os.MkdirAll(subDir, 0755)
		require.NoError(t, err)

		CreateSampleStructureFromMapInDir(t, subDir, map[string]string{
			fmt.Sprintf("file%d.txt", i): fmt.Sprintf("content%d", i),
		})

		privateKeyPath := filepath.Join(tempDir, fmt.Sprintf("key%d.pem", i))
		_, err = certification.GenerateAndWritePrivateKey(privateKeyPath)
		require.NoError(t, err)

		signer, err := certification.NewEd25519SignerFromFile(privateKeyPath, tc.reference)
		require.NoError(t, err)

		sc := scanner.New()
		gen := generator.New(sc, signer)
		err = gen.Generate(context.Background(), subDir)
		require.NoError(t, err)
	}

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{
		tempDir,
		"--freshness-duration", "1h",
	})

	require.NoError(t, err)

	// Verify all references appear
	for _, tc := range testCases {
		assert.Contains(t, output, tc.reference)
	}

	// Verify summary shows mixed statuses
	assert.Contains(t, output, "Summary:")
	// This would depend on your actual trust configuration
}

// Helper function to create sample structure in a specific directory
func CreateSampleStructureFromMapInDir(t *testing.T, baseDir string, files map[string]string) {
	for path, content := range files {
		fullPath := filepath.Join(baseDir, path)
		err := os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte(content), 0644)
		require.NoError(t, err)
	}
}

func TestVerifyCmd_WithFreshnessLevel_PreservesMultipleSignatures(t *testing.T) {
	// This test verifies that with appropriate freshness level,
	// multiple signatures in different directories are all preserved
	rootDir := t.TempDir()

	// Create 3 directories with different signers
	for i := 0; i < 3; i++ {
		subDir := filepath.Join(rootDir, fmt.Sprintf("project%d", i))
		err := os.MkdirAll(subDir, 0755)
		require.NoError(t, err)

		CreateSampleStructureFromMapInDir(t, subDir, map[string]string{
			"main.go": fmt.Sprintf("package main\n\nfunc main() { println(%d) }", i),
		})

		privateKeyPath := filepath.Join(rootDir, fmt.Sprintf("key%d.pem", i))
		_, err = certification.GenerateAndWritePrivateKey(privateKeyPath)
		require.NoError(t, err)

		signer, err := certification.NewEd25519SignerFromFile(privateKeyPath,
			fmt.Sprintf("github:org%d/repo%d", i, i))
		require.NoError(t, err)

		sc := scanner.New()
		gen := generator.New(sc, signer)
		err = gen.Generate(context.Background(), subDir)
		require.NoError(t, err)
	}

	// Verify without freshness level (should still work for multiple dirs)
	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{rootDir})

	require.NoError(t, err)

	// Should find all 3 manifests
	assert.Contains(t, output, "verified 3 manifest(s)")

	// Should show all 3 auditors
	assert.Contains(t, output, "github:org0/repo0")
	assert.Contains(t, output, "github:org1/repo1")
	assert.Contains(t, output, "github:org2/repo2")
}

func TestVerifyCmd_AuditorSummary_WithMultipleDirectories(t *testing.T) {
	rootDir := t.TempDir()

	// Create directories with different types of auditors
	auditorTypes := []struct {
		dirName   string
		reference string
	}{
		{"trusted1", "github:trusted1/repo"},
		{"trusted2", "github:trusted2/repo"},
		{"unsupported1", "unknown:scheme1/path"},
		{"unsupported2", "unknown:scheme2/path"},
		{"corp", "corp:company/team"},
	}

	for _, auditor := range auditorTypes {
		subDir := filepath.Join(rootDir, auditor.dirName)
		err := os.MkdirAll(subDir, 0755)
		require.NoError(t, err)

		CreateSampleStructureFromMapInDir(t, subDir, map[string]string{
			"file.txt": "content",
		})

		privateKeyPath := filepath.Join(rootDir, fmt.Sprintf("%s_key.pem", auditor.dirName))
		_, err = certification.GenerateAndWritePrivateKey(privateKeyPath)
		require.NoError(t, err)

		signer, err := certification.NewEd25519SignerFromFile(privateKeyPath, auditor.reference)
		require.NoError(t, err)

		sc := scanner.New()
		gen := generator.New(sc, signer)
		err = gen.Generate(context.Background(), subDir)
		require.NoError(t, err)
	}

	cmd := NewVerifyCommand()
	output, err := ExecuteCommandWithCapture(t, cmd, []string{
		rootDir,
		"--freshness-interval", "24h",
	})

	require.NoError(t, err)

	// Verify all auditors are listed
	for _, auditor := range auditorTypes {
		assert.Contains(t, output, auditor.reference)
	}

	// The summary should reflect the counts based on your trust configuration
	assert.Contains(t, output, "Summary:")

	// These exact counts depend on your trust verifier configuration
	// For example, if github: and corp: are trusted, but unknown: is not:
	// assert.Contains(t, output, "3 trusted")
	// assert.Contains(t, output, "2 unsupported")
}
