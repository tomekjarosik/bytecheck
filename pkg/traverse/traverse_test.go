package traverse

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helper to create a test directory structure.
// Returns the root temp directory path and a cleanup function.
func createTestDirStructure(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	// Structure to create:
	// tempDir/
	// ├── a/
	// │   ├── a1/
	// │   │   └── file1.txt
	// │   └── a2/
	// │       └── file2.txt
	// ├── b/
	// │   └── file3.txt
	// └── root_file.txt
	structure := []string{
		"a/a1/file1.txt",
		"a/a2/file2.txt",
		"b/file3.txt",
		"root_file.txt",
	}

	for _, p := range structure {
		fullPath := filepath.Join(tempDir, p)
		if strings.HasSuffix(p, ".txt") {
			// It's a file
			if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
				t.Fatalf("Failed to create parent dir for %s: %v", p, err)
			}
			if err := os.WriteFile(fullPath, []byte("test"), 0644); err != nil {
				t.Fatalf("Failed to create file %s: %v", p, err)
			}
		} else {
			// It's a directory (though all are implicitly created)
			if err := os.MkdirAll(fullPath, 0755); err != nil {
				t.Fatalf("Failed to create dir %s: %v", p, err)
			}
		}
	}

	// Create an empty dir for another test case
	if err := os.Mkdir(filepath.Join(tempDir, "c_empty"), 0755); err != nil {
		t.Fatalf("Failed to create empty dir: %v", err)
	}

	return tempDir
}

func TestWalkPostOrder_CorrectOrder(t *testing.T) {
	tempDir := createTestDirStructure(t)

	var processedDirs []string

	walkFn := func(ctx context.Context, dirPath string, err error) error {
		if err != nil {
			t.Errorf("walkFn received unexpected error for %s: %v", dirPath, err)
			return err
		}

		// Get relative path for easier verification
		relPath, relErr := filepath.Rel(tempDir, dirPath)
		if relErr != nil {
			t.Errorf("Failed to get relative path for %s: %v", dirPath, relErr)
			relPath = dirPath
		}

		processedDirs = append(processedDirs, relPath)

		return nil
	}

	ctx := context.Background()
	if err := WalkPostOrder(ctx, tempDir, walkFn); err != nil {
		t.Fatalf("WalkPostOrder failed: %v", err)
	}

	// Expected post-order (subdirs first, sorted alphabetically)
	expectedOrder := []string{
		filepath.Join("a", "a1"), // Deepest in 'a'
		filepath.Join("a", "a2"), // Other branch in 'a'
		"a",                      // Parent 'a'
		"b",                      // 'b' (has no subdirs)
		"c_empty",                // 'c_empty' (has no subdirs)
		".",                      // Root directory last
	}

	if len(processedDirs) != len(expectedOrder) {
		t.Fatalf("Expected %d directories, got %d. Processed: %v",
			len(expectedOrder), len(processedDirs), processedDirs)
	}

	for i, expected := range expectedOrder {
		if processedDirs[i] != expected {
			t.Errorf("Order mismatch at position %d: expected %s, got %s",
				i, expected, processedDirs[i])
		}
	}
	t.Logf("✓ Post-order traversal verified: %v", processedDirs)
}

func TestWalkPostOrder_EmptyDir(t *testing.T) {
	tempDir := t.TempDir()

	var calls int
	var calledPath string

	walkFn := func(ctx context.Context, dirPath string, err error) error {
		if err != nil {
			t.Fatalf("walkFn received unexpected error: %v", err)
		}
		calls++
		calledPath = dirPath
		return nil
	}

	ctx := context.Background()
	if err := WalkPostOrder(ctx, tempDir, walkFn); err != nil {
		t.Fatalf("WalkPostOrder failed: %v", err)
	}

	if calls != 1 {
		t.Errorf("Expected walkFn to be called 1 time, got %d", calls)
	}
	if calledPath != tempDir {
		t.Errorf("Expected walkFn to be called with %s, got %s", tempDir, calledPath)
	}
}

func TestWalkPostOrder_ReadDirError(t *testing.T) {
	// 1. Test non-existent directory
	nonExistentPath := filepath.Join(os.TempDir(), "non-existent-dir-for-test")
	_ = os.Remove(nonExistentPath) // Ensure it's gone

	var calls int
	var receivedErr error
	var receivedPath string

	walkFn := func(ctx context.Context, dirPath string, err error) error {
		calls++
		receivedErr = err
		receivedPath = dirPath
		// We must return the error to propagate it, just as the real WalkPostOrder does
		return err
	}

	ctx := context.Background()
	err := WalkPostOrder(ctx, nonExistentPath, walkFn)

	if err == nil {
		t.Fatal("WalkPostOrder should have returned an error for a non-existent path")
	}
	if calls != 1 {
		t.Errorf("Expected walkFn to be called exactly 1 time, got %d", calls)
	}
	if receivedErr == nil {
		t.Error("Expected walkFn to receive a non-nil error")
	}
	if !errors.Is(receivedErr, os.ErrNotExist) {
		t.Errorf("Expected a 'file does not exist' error, got: %v", receivedErr)
	}
	if receivedPath != nonExistentPath {
		t.Errorf("Expected walkFn to be called with %s, got %s", nonExistentPath, receivedPath)
	}

	// 2. Test permission denied (simulated by a file)
	// We create a file and try to ReadDir it, which will fail.
	tempFile, err := os.CreateTemp("", "traverse_file_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name())

	calls = 0
	receivedErr = nil
	err = WalkPostOrder(ctx, tempFile.Name(), walkFn)

	if err == nil {
		t.Fatal("WalkPostOrder should have returned an error when run on a file")
	}
	if calls != 1 {
		t.Errorf("Expected walkFn to be called exactly 1 time, got %d", calls)
	}
	if receivedErr == nil {
		t.Error("Expected walkFn to receive a non-nil error")
	}
	// Error message can be "not a directory" or "permission denied" depending on OS
	t.Logf("Received expected error for file: %v", receivedErr)
}

func TestWalkPostOrder_WalkFnStopsTraversal(t *testing.T) {
	tempDir := createTestDirStructure(t)

	var processedDirs []string
	stopErr := fmt.Errorf("stop traversal")
	stopPath := filepath.Join("a", "a1") // This will be processed first in its branch

	walkFn := func(ctx context.Context, dirPath string, err error) error {
		if err != nil {
			return err // Propagate read errors
		}

		relPath, _ := filepath.Rel(tempDir, dirPath)

		processedDirs = append(processedDirs, relPath)

		if relPath == stopPath {
			return stopErr
		}
		return nil
	}

	ctx := context.Background()
	err := WalkPostOrder(ctx, tempDir, walkFn)

	if err == nil {
		t.Fatal("WalkPostOrder should have returned an error")
	}
	if err != stopErr {
		t.Fatalf("Expected error %v, got %v", stopErr, err)
	}

	// We expect the walk to have processed "a/a1" and then stopped.
	// Nothing else should be in the list.
	expectedProcessed := []string{stopPath}

	if len(processedDirs) != len(expectedProcessed) {
		t.Fatalf("Expected %d processed dirs, got %d. Processed: %v",
			len(expectedProcessed), len(processedDirs), processedDirs)
	}
	if processedDirs[0] != expectedProcessed[0] {
		t.Errorf("Expected processed list to be %v, got %v", expectedProcessed, processedDirs)
	}
	t.Logf("✓ Traversal stopped as expected: %v", processedDirs)
}
