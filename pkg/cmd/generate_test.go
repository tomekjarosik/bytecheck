package cmd

import (
	"bytes"
	"context"
	"fmt"
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

	// Create and execute command
	cmd := NewGenerateCmd()

	// Capture output
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	// Execute command
	err = cmd.Execute()
	require.NoError(t, err)

	// Verify manifest was created
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	assert.FileExists(t, manifestPath)

	// Verify output contains expected text
	output := stdout.String()
	assert.Contains(t, output, "processed")
	assert.Contains(t, output, "directory")
}

func TestGenerateCmd_WithDirectory(t *testing.T) {
	// Create temporary directory structure
	tempDir := t.TempDir()
	targetDir := filepath.Join(tempDir, "target")
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	// Create test files in target directory
	testFile := filepath.Join(targetDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	// Create subdirectory with file
	subDir := filepath.Join(targetDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	subFile := filepath.Join(subDir, "sub.txt")
	require.NoError(t, os.WriteFile(subFile, []byte("sub content"), 0644))

	// Create and execute command
	cmd := NewGenerateCmd()

	// Capture output
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	// Set arguments
	cmd.SetArgs([]string{targetDir})

	// Execute command
	err := cmd.Execute()
	require.NoError(t, err)

	// Verify manifests were created
	manifestPath := filepath.Join(targetDir, ".bytecheck.manifest")
	assert.FileExists(t, manifestPath)

	subManifestPath := filepath.Join(subDir, ".bytecheck.manifest")
	assert.FileExists(t, subManifestPath)

	// Verify output
	output := stdout.String()
	assert.Contains(t, output, "processed")
	assert.Contains(t, output, "directory")
}

func TestGenerateCmd_NonExistentDirectory(t *testing.T) {
	nonExistentDir := "/path/that/does/not/exist"

	// Create and execute command
	cmd := NewGenerateCmd()

	// Capture output
	var stderr bytes.Buffer
	cmd.SetOut(&stderr)
	cmd.SetErr(&stderr)

	// Set arguments
	cmd.SetArgs([]string{nonExistentDir})

	// Execute command - should fail
	err := cmd.Execute()
	assert.Error(t, err)
}

func TestGenerateCmd_WithNoFreshManifest(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	createFreshManifest(t, tempDir)

	// Create and execute command
	cmd := NewGenerateCmd()

	// Capture output
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	// Set arguments
	cmd.SetArgs([]string{tempDir})

	// Execute command
	err := cmd.Execute()
	require.NoError(t, err)

	// Verify output mentions cached processing
	output := stdout.String()
	assert.Contains(t, output, "processed 1 directory(s) (0 cached)")
}

func TestGenerateCmd_WithLongFreshnessLimitManifest(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	createFreshManifest(t, tempDir)

	// Create and execute command
	cmd := NewGenerateCmd()

	// Capture output
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	// Set arguments
	cmd.SetArgs([]string{tempDir, "--freshness-interval", "1h"})

	// Execute command
	err := cmd.Execute()
	require.NoError(t, err)

	// Verify output mentions cached processing
	output := stdout.String()
	assert.Contains(t, output, "processed 1 directory(s) (1 cached)")
}

func TestGenerateCmd_WithLongFreshnessLimitButCorruptedManifest(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0644))

	// Create fresh manifest
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	manifestContent := `{
		  "entities": [
			{
			  "name": "test",
			  "checksum": "xc17022aabcf48e38969f330d4b35f15c2e40023b1e4ffb8a7c7e86aabf7356a",
			  "isDir": true
			},
			{
			  "name": "config.go",
			  "checksum": "52729c59f0a01d7982cfb541b7eae6ed9f9064ba704121bf6ebf33ebe3ea1efc",
			  "isDir": false
			}
		  ],
		  "hmac": "05c4a0eb225733eb0f82914a6e47a54fe56b822aacbb6947d52566bb45e724ec"
		}`
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifestContent), 0644))

	// Ensure the manifest is fresh by touching it
	now := time.Now()
	require.NoError(t, os.Chtimes(manifestPath, now, now))

	cmd := NewGenerateCmd()

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	cmd.SetArgs([]string{tempDir, "--freshness-interval", "1h"})

	err := cmd.Execute()
	require.ErrorContains(t, err, "invalid HMAC")
}

func TestGenerateCmd_ContextCancellation(t *testing.T) {
	// Create temporary directory with files
	tempDir := t.TempDir()

	// Create many files to make the operation take some time
	for i := 0; i < 10; i++ {
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
	cmd.SetArgs([]string{tempDir})

	// Capture output
	var stderr bytes.Buffer
	cmd.SetOut(&stderr)
	cmd.SetErr(&stderr)

	// Execute command - should be cancelled
	err := cmd.Execute()

	// Should get context cancellation error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context")
}

func TestGenerateCmd_EmptyDirectory(t *testing.T) {
	// Create empty temporary directory
	tempDir := t.TempDir()

	// Create and execute command
	cmd := NewGenerateCmd()

	// Capture output
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	// Set arguments
	cmd.SetArgs([]string{tempDir})

	// Execute command
	err := cmd.Execute()
	require.NoError(t, err)

	// Verify empty manifest was created
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	assert.FileExists(t, manifestPath)

	// Verify output
	output := stdout.String()
	assert.Contains(t, output, "processed")
}

func TestGenerateCmd_PermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping permission test when running as root")
	}

	// Create temporary directory
	tempDir := t.TempDir()
	restrictedDir := filepath.Join(tempDir, "restricted")
	require.NoError(t, os.MkdirAll(restrictedDir, 0755))

	// Create a file in the restricted directory
	testFile := filepath.Join(restrictedDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	// Remove read permissions from the directory
	require.NoError(t, os.Chmod(restrictedDir, 0000))
	defer os.Chmod(restrictedDir, 0755) // Restore permissions for cleanup

	// Create and execute command
	cmd := NewGenerateCmd()

	// Capture output
	var stderr bytes.Buffer
	cmd.SetOut(&stderr)
	cmd.SetErr(&stderr)

	// Set arguments
	cmd.SetArgs([]string{restrictedDir})

	// Execute command - should fail due to permissions
	err := cmd.Execute()
	assert.Error(t, err)
}

// Benchmark test to ensure the command performs reasonably
func BenchmarkGenerateCmd(b *testing.B) {
	// Create temporary directory with test files
	tempDir := b.TempDir()

	// Create several test files
	for i := 0; i < 10; i++ {
		testFile := filepath.Join(tempDir, fmt.Sprintf("test%d.txt", i))
		content := bytes.Repeat([]byte("test content "), 100) // ~1.3KB per file
		require.NoError(b, os.WriteFile(testFile, content, 0644))
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Create fresh command for each iteration
		cmd := NewGenerateCmd()

		// Discard output
		cmd.SetOut(os.NewFile(0, os.DevNull))
		cmd.SetErr(os.NewFile(0, os.DevNull))

		// Set arguments
		cmd.SetArgs([]string{tempDir})

		// Execute command
		err := cmd.Execute()
		require.NoError(b, err)

		// Clean up manifest for next iteration
		manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
		os.Remove(manifestPath)
	}
}

// Test helper to verify command integration
func TestGenerateCmd_Integration(t *testing.T) {
	// Create a complex directory structure
	tempDir := t.TempDir()

	// Root level files
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "root.txt"), []byte("root content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "root2.txt"), []byte("root2 content"), 0644))

	// Subdirectory with files
	subDir1 := filepath.Join(tempDir, "sub1")
	require.NoError(t, os.MkdirAll(subDir1, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir1, "sub1.txt"), []byte("sub1 content"), 0644))

	// Nested subdirectory
	subDir2 := filepath.Join(subDir1, "nested")
	require.NoError(t, os.MkdirAll(subDir2, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir2, "nested.txt"), []byte("nested content"), 0644))

	// Execute command
	cmd := NewGenerateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{tempDir})

	err := cmd.Execute()
	require.NoError(t, err)

	// Verify all manifests were created
	expectedManifests := []string{
		filepath.Join(tempDir, ".bytecheck.manifest"),
		filepath.Join(subDir1, ".bytecheck.manifest"),
		filepath.Join(subDir2, ".bytecheck.manifest"),
	}

	for _, manifest := range expectedManifests {
		assert.FileExists(t, manifest, "Expected manifest: %s", manifest)
	}

	// Verify output contains reasonable information
	output := stdout.String()
	assert.Contains(t, output, "processed")
	assert.Contains(t, output, "directory")
}

func createFreshManifest(t *testing.T, tempDir string) {
	manifestPath := filepath.Join(tempDir, ".bytecheck.manifest")
	manifestContent := `{
		  "entities": [
			{
			  "name": "test",
			  "checksum": "3c17022aabcf48e38969f330d4b35f15c2e40023b1e4ffb8a7c7e86aabf7356a",
			  "isDir": true
			},
			{
			  "name": "config.go",
			  "checksum": "52729c59f0a01d7982cfb541b7eae6ed9f9064ba704121bf6ebf33ebe3ea1efc",
			  "isDir": false
			}
		  ],
		  "hmac": "05c4a0eb225733eb0f82914a6e47a54fe56b822aacbb6947d52566bb45e724ec"
		}`
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifestContent), 0644))
	now := time.Now()
	require.NoError(t, os.Chtimes(manifestPath, now, now))
}
