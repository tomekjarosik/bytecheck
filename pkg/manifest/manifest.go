package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

var DefaultName = ".bytecheck.manifest"

type Entity struct {
	Name     string `json:"name"`
	Checksum string `json:"checksum"`
	IsDir    bool   `json:"isDir"`
}

type Manifest struct {
	Entities []Entity `json:"entities"`
	HMAC     string   `json:"hmac"`
}

// New creates a new manifest with the given entities
func New(entities []Entity) *Manifest {
	return &Manifest{
		Entities: entities,
	}
}

// LoadManifest loads a manifest from the given directory
func LoadManifest(manifestPath string) (*Manifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No manifest exists
		}
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	loadedHMAC := m.HMAC
	err = m.calculateHMAC()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate HMAC: %w", err)
	}
	if loadedHMAC != m.HMAC {
		return nil, fmt.Errorf("invalid HMAC")
	}

	return &m, nil
}

// Save saves the manifest to the given directory
func (m *Manifest) Save(manifestPath string) error {
	if err := m.calculateHMAC(); err != nil {
		return fmt.Errorf("failed to calculate HMAC: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	return os.WriteFile(manifestPath, data, 0644)
}

// Touch updates the manifest file's modification time without changing content
func (m *Manifest) Touch(manifestPath string) error {
	// Update the file's access and modification time to now
	now := time.Now()
	return os.Chtimes(manifestPath, now, now)
}

// GetModTime returns the manifest file's modification time
func GetModTime(manifestPath string) (time.Time, error) {

	info, err := os.Stat(manifestPath)
	if err != nil {
		return time.Time{}, err
	}

	return info.ModTime(), nil
}

func LoadManifestIfFresh(manifestPath string, freshnessLimit *time.Duration) (*Manifest, error) {
	if freshnessLimit == nil {
		return nil, nil
	}

	modTime, err := GetModTime(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No manifest exists
		}
		return nil, err
	}
	age := time.Since(modTime)
	if age > *freshnessLimit {
		return nil, nil
	}
	m, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// calculateHMAC computes HMAC for the manifest (excluding the HMAC field itself)
func (m *Manifest) calculateHMAC() error {
	// Create a copy without HMAC to avoid circular dependency
	manifestCopy := &Manifest{
		Entities: m.Entities,
		// HMAC field is omitted
	}

	data, err := json.Marshal(manifestCopy)
	if err != nil {
		return err
	}

	m.HMAC = calculateHMAC(data)
	return nil
}
