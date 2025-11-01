package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNew tests the creation of new manifests
func TestNew(t *testing.T) {
	entities := []Entity{
		{Name: "file1.txt", Checksum: "abc123", IsDir: false},
		{Name: "dir1", Checksum: "def456", IsDir: true},
	}

	m := New(entities)

	if m == nil {
		t.Fatal("New() returned nil")
	}

	if len(m.Entities) != 2 {
		t.Errorf("Expected 2 entities, got %d", len(m.Entities))
	}

	if m.Entities[0].Name != "file1.txt" {
		t.Errorf("Expected first entity name 'file1.txt', got '%s'", m.Entities[0].Name)
	}

	if m.Entities[1].IsDir != true {
		t.Errorf("Expected second entity to be directory")
	}
}

// TestNewEmptyManifest tests creating manifest with no entities
func TestNewEmptyManifest(t *testing.T) {
	m := New([]Entity{})

	if m == nil {
		t.Fatal("New() returned nil for empty entities")
	}

	if len(m.Entities) != 0 {
		t.Errorf("Expected 0 entities, got %d", len(m.Entities))
	}
}

// TestSaveAndLoad tests saving and loading manifests
func TestSaveAndLoad(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "manifest_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manifestPath := filepath.Join(tempDir, "manifest.txt")

	// Create test manifest
	entities := []Entity{
		{Name: "README.md", Checksum: "a1b2c3d4", IsDir: false},
		{Name: "src", Checksum: "e5f6g7h8", IsDir: true},
		{Name: "main.go", Checksum: "i9j0k1l2", IsDir: false},
	}
	originalManifest := New(entities)

	// Save the manifest
	err = originalManifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Check that manifest file was created
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Fatal("Manifest file was not created")
	}

	// Load the manifest back
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

	for i, original := range originalManifest.Entities {
		loaded := loadedManifest.Entities[i]
		if original.Name != loaded.Name {
			t.Errorf("Entity %d name mismatch: expected '%s', got '%s'",
				i, original.Name, loaded.Name)
		}
		if original.Checksum != loaded.Checksum {
			t.Errorf("Entity %d checksum mismatch: expected '%s', got '%s'",
				i, original.Checksum, loaded.Checksum)
		}
		if original.IsDir != loaded.IsDir {
			t.Errorf("Entity %d IsDir mismatch: expected %t, got %t",
				i, original.IsDir, loaded.IsDir)
		}
	}

	t.Log("✓ Save and load completed successfully")
}

// TestLoadNonExistentManifest tests loading from directory without manifest
func TestLoadNonExistentManifest(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "manifest_test_empty")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	manifestPath := filepath.Join(tempDir, "manifest.txt")

	// Try to load manifest from empty directory
	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Errorf("LoadManifest should not return error for non-existent manifest, got: %v", err)
	}

	if manifest != nil {
		t.Error("LoadManifest should return nil for non-existent manifest")
	}

	t.Log("✓ Non-existent manifest handled correctly")
}

// TestLoadInvalidManifest tests loading corrupted manifest files
func TestLoadInvalidManifest(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "manifest_test_invalid")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manifestPath := filepath.Join(tempDir, "manifest.txt")
	invalidJSON := `{"entities": [{"name": "incomplete"`
	err = os.WriteFile(manifestPath, []byte(invalidJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid manifest file: %v", err)
	}

	// Try to load invalid manifest
	manifest, err := LoadManifest(manifestPath)
	if err == nil {
		t.Error("LoadManifest should return error for invalid JSON")
	}

	if manifest != nil {
		t.Error("LoadManifest should return nil manifest for invalid JSON")
	}

	if !strings.Contains(err.Error(), "failed to parse manifest") {
		t.Errorf("Error message should mention parsing failure, got: %v", err)
	}

	t.Log("✓ Invalid manifest handled correctly")
}

// TestJSONFormat tests the JSON format of saved manifests
func TestJSONFormat(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "manifest_test_json")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	manifestPath := filepath.Join(tempDir, "manifest.txt")
	// Create test manifest
	entities := []Entity{
		{Name: "file.txt", Checksum: "checksum123", IsDir: false},
		{Name: "directory", Checksum: "checksum456", IsDir: true},
	}
	manifest := New(entities)

	// Save manifest
	err = manifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Read the raw JSON file

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read manifest file: %v", err)
	}

	// Check that JSON is properly formatted (indented)
	jsonStr := string(data)
	if !strings.Contains(jsonStr, "  ") {
		t.Error("JSON should be indented for readability")
	}

	// Parse JSON to verify structure
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	if err != nil {
		t.Fatalf("Saved manifest is not valid JSON: %v", err)
	}

	// Check structure - fix the variable name conflict
	entitiesField, exists := parsed["entities"]
	if !exists {
		t.Error("JSON should contain 'entities' field")
	}

	entitiesArray, ok := entitiesField.([]interface{})
	if !ok {
		t.Error("'entities' field should be an array")
	}

	if len(entitiesArray) != 2 {
		t.Errorf("Expected 2 entities in JSON, got %d", len(entitiesArray))
	}

	t.Log("✓ JSON format validation completed")
}

// TestTouch tests the Touch functionality
func TestTouch(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "manifest_test_touch")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manifestPath := filepath.Join(tempDir, "manifest.txt")

	// Create and save manifest
	manifest := New([]Entity{{Name: "test.txt", Checksum: "abc123", IsDir: false}})
	err = manifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Get initial modification time
	initialModTime, err := GetModTime(tempDir)
	if err != nil {
		t.Fatalf("Failed to get initial mod time: %v", err)
	}

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Touch the manifest
	err = manifest.Touch(tempDir)
	if err != nil {
		t.Fatalf("Failed to touch manifest: %v", err)
	}

	// Get new modification time
	newModTime, err := GetModTime(tempDir)
	if err != nil {
		t.Fatalf("Failed to get new mod time: %v", err)
	}

	// Check that modification time was updated
	if !newModTime.After(initialModTime) {
		t.Error("Touch should update modification time")
	}

	// Verify content wasn't changed by loading manifest
	loadedManifest, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("Failed to load manifest after touch: %v", err)
	}

	if len(loadedManifest.Entities) != 1 {
		t.Error("Touch should not change manifest content")
	}

	if loadedManifest.Entities[0].Checksum != "abc123" {
		t.Error("Touch should not change manifest content")
	}

	t.Log("✓ Touch functionality works correctly")
}

// TestGetModTime tests GetModTime function
func TestGetModTime(t *testing.T) {
	tempDir := t.TempDir()

	manifestPath := filepath.Join(tempDir, "manifest.txt")

	_, err := GetModTime(manifestPath)
	if err == nil {
		t.Error("GetModTime should return error for non-existent manifest")
	}

	// Create manifest
	manifest := New([]Entity{{Name: "test.txt", Checksum: "abc123", IsDir: false}})
	err = manifest.Save(manifestPath)
	if err != nil {
		t.Fatalf("Failed to save manifest: %v", err)
	}

	// Get modification time
	modTime, err := GetModTime(manifestPath)
	if err != nil {
		t.Fatalf("Failed to get mod time: %v", err)
	}

	// Check that we got a reasonable time (within last minute)
	now := time.Now()
	if modTime.After(now) {
		t.Error("Modification time cannot be in the future")
	}

	if now.Sub(modTime) > time.Minute {
		t.Error("Modification time should be recent")
	}

	t.Log("✓ GetModTime works correctly")
}

// TestEntityStruct tests the Entity struct
func TestEntityStruct(t *testing.T) {
	entity := Entity{
		Name:     "test_file.txt",
		Checksum: "sha256_checksum_here",
		IsDir:    false,
	}

	// Test JSON marshaling/unmarshaling
	data, err := json.Marshal(entity)
	if err != nil {
		t.Fatalf("Failed to marshal entity: %v", err)
	}

	var unmarshaled Entity
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal entity: %v", err)
	}

	if unmarshaled.Name != entity.Name {
		t.Errorf("Name mismatch after JSON roundtrip: expected '%s', got '%s'",
			entity.Name, unmarshaled.Name)
	}

	if unmarshaled.Checksum != entity.Checksum {
		t.Errorf("Checksum mismatch after JSON roundtrip: expected '%s', got '%s'",
			entity.Checksum, unmarshaled.Checksum)
	}

	if unmarshaled.IsDir != entity.IsDir {
		t.Errorf("IsDir mismatch after JSON roundtrip: expected %t, got %t",
			entity.IsDir, unmarshaled.IsDir)
	}

	t.Log("✓ Entity struct works correctly")
}

// BenchmarkSaveManifest benchmarks manifest saving
func BenchmarkSaveManifest(b *testing.B) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "manifest_benchmark")
	if err != nil {
		b.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a manifest with many entities
	entities := make([]Entity, 1000)
	for i := 0; i < 1000; i++ {
		entities[i] = Entity{
			Name:     fmt.Sprintf("file_%d.txt", i),
			Checksum: fmt.Sprintf("checksum_%d", i),
			IsDir:    i%10 == 0, // Every 10th is a directory
		}
	}

	manifest := New(entities)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := manifest.Save(tempDir)
		if err != nil {
			b.Fatalf("Failed to save manifest: %v", err)
		}
	}
}

// BenchmarkLoadManifest benchmarks manifest loading
func BenchmarkLoadManifest(b *testing.B) {
	// Create temporary directory and manifest
	tempDir, err := os.MkdirTemp("", "manifest_benchmark_load")
	if err != nil {
		b.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create and save a large manifest
	entities := make([]Entity, 1000)
	for i := 0; i < 1000; i++ {
		entities[i] = Entity{
			Name:     fmt.Sprintf("file_%d.txt", i),
			Checksum: fmt.Sprintf("checksum_%d", i),
			IsDir:    i%10 == 0,
		}
	}

	manifest := New(entities)
	err = manifest.Save(tempDir)
	if err != nil {
		b.Fatalf("Failed to save manifest: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadManifest(tempDir)
		if err != nil {
			b.Fatalf("Failed to load manifest: %v", err)
		}
	}
}
