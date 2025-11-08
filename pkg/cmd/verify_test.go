package cmd

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	gen := generator.New(sc)
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
	gen := generator.New(sc)
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
	gen := generator.New(sc)
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
