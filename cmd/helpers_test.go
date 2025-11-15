package cmd

import (
	"bytes"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ExecuteCommandWithCapture executes a cobra command and captures its output
func ExecuteCommandWithCapture(t testing.TB, cmd *cobra.Command, args []string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return stdout.String(), err
}

func CreateFreshManifest(t *testing.T, tempDir string) (manifestPath string) {
	t.Helper()
	manifestPath = filepath.Join(tempDir, ".bytecheck.manifest")
	manifestContent := `{
  "entities": [
    {
      "name": "config.go",
      "checksum": "52729c59f0a01d7982cfb541b7eae6ed9f9064ba704121bf6ebf33ebe3ea1efc",
      "isDir": false
    },
    {
      "name": "test",
      "checksum": "3c17022aabcf48e38969f330d4b35f15c2e40023b1e4ffb8a7c7e86aabf7356a",
      "isDir": true
    }
  ],
  "hmac": "87024b7993879875c3909b7acfd0256933d4b72539c24d9ad0071ba6f2ffee26"
}`
	require.NoError(t, os.WriteFile(manifestPath, []byte(manifestContent), 0644))
	now := time.Now()
	require.NoError(t, os.Chtimes(manifestPath, now, now))
	return
}

// CorruptFileByOneByte takes a file path, opens the file,
// selects a random byte, and modifies it.
// This is useful for testing file integrity checks.
func CorruptFileByOneByte(t *testing.T, filepath string, seed int64) error {
	t.Helper()

	file, err := os.OpenFile(filepath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("could not get file stats: %w", err)
	}

	size := fileInfo.Size()
	if size == 0 {
		return fmt.Errorf("file is empty, cannot corrupt")
	}

	r := rand.New(rand.NewSource(seed))
	offset := r.Int63n(size)

	_, err = file.Seek(offset, io.SeekStart) // io.SeekStart means offset from the beginning
	if err != nil {
		return fmt.Errorf("could not seek to offset %d: %w", offset, err)
	}

	readBuffer := make([]byte, 1)
	_, err = file.Read(readBuffer)
	if err != nil {
		// This handles potential read errors, even if we're at the selected offset
		return fmt.Errorf("could not read byte at offset %d: %w", offset, err)
	}
	originalByte := readBuffer[0]

	// A simple way to guarantee a change is to just add 1.
	// A 'byte' is a uint8, so 255 will automatically wrap to 0.
	newByte := originalByte + 1

	// After reading, the file cursor moved, so we must return to the offset.
	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		return fmt.Errorf("could not seek back to offset %d: %w", offset, err)
	}

	writeBuffer := []byte{newByte}
	_, err = file.Write(writeBuffer)
	if err != nil {
		return fmt.Errorf("could not write new byte at offset %d: %w", offset, err)
	}

	fmt.Printf("--- Corruption successful at offset %d: 0x%X -> 0x%X ---\n", offset, originalByte, newByte)
	return nil
}

// SampleFile represents a file in the test structure
type SampleFile struct {
	Path     string        // Relative path from base directory
	Content  string        // File content (random if empty)
	Modified time.Duration // Relative modified time (e.g., -2*time.Hour for 2 hours ago)
}

// SampleDir represents a directory in the test structure
type SampleDir struct {
	Path string
}

// SampleStructure defines the complete directory/file structure
type SampleStructure struct {
	BaseDir string // If empty, uses t.TempDir()
	Files   []SampleFile
	Dirs    []SampleDir // Optional: explicit directory creation
}

// generateRandomContent creates random content if none provided
func generateRandomContent() string {
	bytes := make([]byte, 100) // 100 random bytes
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based content if crypto fails
		return fmt.Sprintf("random_content_%d", time.Now().UnixNano())
	}
	return string(bytes)
}

// CreateSampleStructure creates a complete test directory structure
func CreateSampleStructure(t *testing.T, structure SampleStructure) string {
	t.Helper()

	baseDir := structure.BaseDir
	if baseDir == "" {
		baseDir = t.TempDir()
	}

	// Create explicit directories first
	for _, dir := range structure.Dirs {
		fullPath := filepath.Join(baseDir, dir.Path)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", fullPath, err)
		}
	}

	// Create files
	for _, file := range structure.Files {
		fullPath := filepath.Join(baseDir, file.Path)

		// Ensure parent directory exists
		parentDir := filepath.Dir(fullPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			t.Fatalf("Failed to create parent directory %s: %v", parentDir, err)
		}

		// Use provided content or generate random content
		content := file.Content
		if content == "" {
			content = generateRandomContent()
		}

		// Create the file
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}

		// Set modified time if specified
		if file.Modified != 0 {
			modifiedTime := time.Now().Add(file.Modified)
			if err := os.Chtimes(fullPath, modifiedTime, modifiedTime); err != nil {
				t.Fatalf("Failed to set modified time for %s: %v", fullPath, err)
			}
		}
	}

	return baseDir
}

// CreateSampleStructureFromMap creates structure from a simple map for quick setup
func CreateSampleStructureFromMap(t *testing.T, files map[string]string) string {
	t.Helper()

	tempDir := t.TempDir()
	var sampleFiles []SampleFile

	for path, content := range files {
		sampleFiles = append(sampleFiles, SampleFile{
			Path:    path,
			Content: content,
		})
	}

	structure := SampleStructure{
		BaseDir: tempDir,
		Files:   sampleFiles,
	}

	return CreateSampleStructure(t, structure)
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
