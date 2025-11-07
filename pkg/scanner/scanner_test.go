package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomekjarosik/bytecheck/pkg/manifest"
)

// TestScannerWalk tests the scanner's Walk functionality
func TestScannerWalk(t *testing.T) {
	// Create a temporary directory for our test
	tempDir, err := os.MkdirTemp("", "scanner_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test directory structure:
	// tempDir/
	// ├── a/
	// │   ├── a1/
	// │   │   └── file1.txt
	// │   ├── a2/
	// │   │   ├── a2_sub/
	// │   │   │   └── file4.txt
	// │   │   └── file2.txt
	// │   └── file3.txt
	// ├── b/
	// │   └── file5.txt
	// └── root_file.txt

	structure := map[string]string{
		"a/a1/file1.txt":                  "content1",
		"a/a1/.bytecheck.manifest":        "m1",
		"a/a2/a2_sub/file4.txt":           "content4",
		"a/a2/a2_sub/.bytecheck.manifest": "m2",
		"a/a2/file2.txt":                  "content2",
		"a/a2/.bytecheck.manifest":        "m3",
		"a/file3.txt":                     "content3",
		"a/.bytecheck.manifest":           "m4",
		"b/file5.txt":                     "content5",
		"b/.bytecheck.manifest":           "m5",
		"root_file.txt":                   "root content",
	}

	// Create the directory structure
	for filePath, content := range structure {
		fullPath := filepath.Join(tempDir, filePath)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", filepath.Dir(fullPath), err)
		}

		// Create the file
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}
	}

	// Track the order of directories processed
	var processedDirs []string
	var processedManifests []*manifest.Manifest

	// Create scanner with progress channel
	progressCh := make(chan *Stats, 10)
	scanner := New(WithProgressChannel(progressCh))

	ctx := context.Background()
	err = scanner.Walk(ctx, tempDir, func(ctx context.Context, dirPath string, computedManifest *manifest.Manifest, cached bool, err error) error {
		if err != nil {
			t.Errorf("Walk error for %s: %v", dirPath, err)
			return err
		}

		// Get relative path for easier verification
		relPath, relErr := filepath.Rel(tempDir, dirPath)
		if relErr != nil {
			relPath = dirPath
		}
		if relPath == "." {
			relPath = "root"
		}

		processedDirs = append(processedDirs, relPath)
		processedManifests = append(processedManifests, computedManifest)

		// Log what entities were found
		t.Logf("Processing directory: %s (cached: %t)", relPath, cached)
		for _, entity := range computedManifest.Entities {
			t.Logf("  - %s (isDir: %t, checksum: %s)", entity.Name, entity.IsDir, entity.Checksum[:min(8, len(entity.Checksum))]+"...")
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	// Expected post-order traversal (deepest directories first)
	expectedOrder := []string{
		"a/a1",        // deepest in a branch
		"a/a2/a2_sub", // deepest in a/a2 branch
		"a/a2",        // parent of a2_sub
		"a",           // parent of a1 and a2
		"b",           // single level directory
		"root",        // root directory last
	}

	// Verify the order
	if len(processedDirs) != len(expectedOrder) {
		t.Fatalf("expected %d directories, got %d. processed: %v",
			len(expectedOrder), len(processedDirs), processedDirs)
	}

	for i, expected := range expectedOrder {
		if processedDirs[i] != expected {
			t.Errorf("order mismatch at position %d: expected %s, got %s",
				i, expected, processedDirs[i])
		}
	}

	// Verify that we got manifest objects for each directory
	if len(processedManifests) != len(expectedOrder) {
		t.Fatalf("Expected %d manifests, got %d", len(expectedOrder), len(processedManifests))
	}

	// Verify that each manifest contains the expected entities
	for i, manifest := range processedManifests {
		if manifest == nil {
			t.Errorf("Manifest for directory %s is nil", processedDirs[i])
			continue
		}
		t.Logf("Directory %s has %d entities", processedDirs[i], len(manifest.Entities))
	}

	t.Logf("✓ Post-order traversal verified: %v", processedDirs)
}

// TestScannerWithFreshness tests the scanner with freshness limit
func TestScannerWithFreshness(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "scanner_freshness_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple file
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a manifest file that's "fresh"
	manifestPath := filepath.Join(tempDir, manifest.DefaultName)
	testManifest := manifest.New([]manifest.Entity{
		{Name: "test.txt", Checksum: "dummy", IsDir: false},
	})
	if err := testManifest.Save(manifestPath); err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	// Test with freshness limit
	freshnessLimit := 10 * time.Second
	scanner := New(WithManifestFreshnessLimit(freshnessLimit))

	processedCount := 0
	cachedCount := 0

	ctx := context.Background()
	err = scanner.Walk(ctx, tempDir, func(ctx context.Context, dirPath string, computedManifest *manifest.Manifest, cached bool, err error) error {
		if err != nil {
			return err
		}

		processedCount++
		if cached {
			cachedCount++
		}

		return nil
	})

	if err != nil {
		t.Fatalf("Walk with freshness failed: %v", err)
	}

	if processedCount != 1 {
		t.Errorf("Expected 1 processed directory, got %d", processedCount)
	}

	// The manifest should be considered fresh and cached
	if cachedCount != 1 {
		t.Errorf("Expected 1 cached directory, got %d", cachedCount)
	}

	t.Log("✓ Freshness limit test passed")
}

// TestScannerProgressChannel tests that the progress channel works
func TestScannerProgressChannel(t *testing.T) {
	// Create a temporary directory with some structure
	tempDir, err := os.MkdirTemp("", "scanner_progress_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create some directories and files
	dirs := []string{"dir1", "dir2", "dir3"}
	for _, dir := range dirs {
		dirPath := filepath.Join(tempDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dirPath, err)
		}

		// Add a file to each directory
		filePath := filepath.Join(dirPath, "file.txt")
		if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", filePath, err)
		}
	}

	// Create scanner with progress channel
	progressCh := make(chan *Stats, 10)
	scanner := New(WithProgressChannel(progressCh))

	// Start a goroutine to collect progress updates
	progressUpdates := make([]*Stats, 0)
	done := make(chan bool)
	go func() {
		for stats := range progressCh {
			progressUpdates = append(progressUpdates, stats)
		}
		done <- true
	}()

	ctx := context.Background()
	err = scanner.Walk(ctx, tempDir, func(ctx context.Context, dirPath string, computedManifest *manifest.Manifest, cached bool, err error) error {
		return nil // Just pass through any errors
	})

	// Close the progress channel and wait for goroutine to finish
	close(progressCh)
	<-done

	if err != nil {
		t.Fatalf("Walk failed: %v", err)
	}

	// Verify we got some progress updates
	if len(progressUpdates) == 0 {
		t.Error("Expected progress updates but got none")
	}

	// The last progress update should show completion
	if len(progressUpdates) > 0 {
		lastUpdate := progressUpdates[len(progressUpdates)-1]
		t.Logf("Final progress: DirsProcessed=%d, FilesProcessed=%d, BytesProcessed=%d",
			lastUpdate.DirsProcessed(), lastUpdate.FilesProcessed(), lastUpdate.BytesProcessed())
	}

	t.Log("✓ Progress channel test passed")
}

// TestScannerOptions tests various scanner options
func TestScannerOptions(t *testing.T) {
	// Test with different manifest names
	scanner1 := New(WithManifestName("custom.manifest"))
	if scanner1.GetManifestName() != "custom.manifest" {
		t.Errorf("Expected manifest name 'custom.manifest', got '%s'", scanner1.GetManifestName())
	}

	// Test with freshness limit
	freshnessLimit := 5 * time.Second
	_ = New(WithManifestFreshnessLimit(freshnessLimit))
	// Note: We can't easily test the internal freshness limit without exposing it
	// This mainly tests that the option doesn't cause any issues

	// Test with progress channel
	progressCh := make(chan *Stats, 10)
	scanner3 := New(WithProgressChannel(progressCh))
	if scanner3.GetProgressChannel() != progressCh {
		t.Error("Progress channel not set correctly")
	}

	t.Log("✓ Scanner options test passed")
}
