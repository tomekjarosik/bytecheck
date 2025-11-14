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
	privateKeyPath := filepath.Join(tempDir2, "key")
	_, _, err := certification.GenerateKeyPair(privateKeyPath, privateKeyPath+".pub")
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
	_, _, err := certification.GenerateKeyPair(privateKeyPath, privateKeyPath+".pub")
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

func TestVerifyCmd_WhenSigned_WithMultipleUnsupportedAuditors_mustShowAuditorsAsUnsupported(t *testing.T) {
	// Create multiple directories, each with their own signer
	directories := make([]string, 0)
	signers := []struct {
		reference string
		keyName   string
	}{
		{"custom:user1", "user1key"},
		{"custom:user2", "user2key"},
		{"corp:team/project", "corpkey3"},
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
		_, _, err = certification.GenerateKeyPair(privateKeyPath, privateKeyPath+".pub")
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
	privateKeyPath := filepath.Join(tempDir, "userkey4")
	_, _, err := certification.GenerateKeyPair(privateKeyPath, privateKeyPath+".pub")
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
	assert.Contains(t, output, "audited by \u001B[36mcustom:toplevel\u001B[0m \u001B[33m[unsupported]\u001B[0m")
	assert.Contains(t, output, "audited by \u001B[36mcustom:user1\u001B[0m \u001B[33m[unsupported]\u001B[0m")
	assert.Contains(t, output, "audited by \u001B[36mcustom:user2\u001B[0m \u001B[33m[unsupported]\u001B[0m")
	assert.Contains(t, output, "audited by \u001B[36mcorp:team/project\u001B[0m \u001B[33m[unsupported]\u001B[0m")

	// Verify all manifests were processed
	assert.Contains(t, output, "verified 4 manifest(s)")
}

func TestVerifyCmd_SignedWithAuditor_mustShowCorrectAuditorStatus(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		name           string
		reference      string
		keyPair        string
		expectedStatus string // "trusted", "unsupported", etc.
		wrongKey       bool
	}{
		{
			name:           "trusted user",
			reference:      "custom:testuser",
			keyPair:        "testuser",
			expectedStatus: "audited by \u001B[36mcustom:testuser\u001B[0m \u001B[32m[trusted]\u001B[0m",
		},
		{
			name:           "unsupported scheme",
			reference:      "unknown:scheme/path",
			keyPair:        "testuser",
			expectedStatus: "unsupported",
		},
		{
			name:           "missing key",
			reference:      "custom:wrong-auditor",
			keyPair:        "testuser",
			expectedStatus: "audited by \u001B[36mcustom:wrong-auditor\u001B[0m \u001B[31m[error: could not fetch keys ",
		},
		{
			name:           "trusted user",
			reference:      "custom:testuser",
			keyPair:        "testuser",
			wrongKey:       true,
			expectedStatus: "audited by \u001B[36mcustom:testuser\u001B[0m \u001B[33m[fishy: one or more public keys for issuer 'custom:testuser' not found in trusted source]",
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			subDir := filepath.Join(tempDir, fmt.Sprintf("dir%d", i))
			err := os.MkdirAll(subDir, 0755)
			require.NoError(t, err)

			CreateSampleStructureFromMapInDir(t, subDir, map[string]string{
				fmt.Sprintf("file%d.txt", i): fmt.Sprintf("content%d", i),
			})
			privateKeyPath := filepath.Join(tempDir, tc.keyPair)
			_, _, err = certification.GenerateKeyPair(privateKeyPath, privateKeyPath+".pub")
			require.NoError(t, err)

			signer, err := certification.NewEd25519SignerFromFile(privateKeyPath, tc.reference)
			require.NoError(t, err)

			sc := scanner.New()
			gen := generator.New(sc, signer)
			err = gen.Generate(context.Background(), subDir)
			require.NoError(t, err)

			if tc.wrongKey {
				// overwrite key used to signing
				privateKeyPath = filepath.Join(tempDir, tc.keyPair)
				_, _, err = certification.GenerateKeyPair(privateKeyPath, privateKeyPath+".pub")
				require.NoError(t, err)
			}

			os.Setenv("BYTECHECK_CUSTOM_AUDITOR_VERIFIER_URL_TEMPLATE", "file://"+tempDir+"/%s.pub")
			defer os.Unsetenv("BYTECHECK_CUSTOM_AUDITOR_VERIFIER_URL_TEMPLATE")
			cmd := NewVerifyCommand()
			output, err := ExecuteCommandWithCapture(t, cmd, []string{subDir})
			require.NoError(t, err)
			assert.Contains(t, output, tc.reference)
			assert.Contains(t, output, tc.expectedStatus)
		})

	}
}
