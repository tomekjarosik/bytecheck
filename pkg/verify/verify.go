package verify

import (
	"context"
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"path/filepath"
)

// DirectoryFailure represents a failed directory verification with detailed information
type DirectoryFailure struct {
	Path        string
	Differences []manifest.EntityDifference
}

// Result represents the result of a verification operation
type Result struct {
	ManifestsFound    int
	ManifestsVerified int
	ManifestSkipped   int
	AllValid          bool
	Failures          []DirectoryFailure
	Stats             *scanner.Stats
}

func (r *Result) ReportDirectoryFailure(rootPath, dirPath string, differences []manifest.EntityDifference) {
	r.AllValid = false
	relPath, pathErr := filepath.Rel(rootPath, dirPath)
	if pathErr != nil {
		relPath = dirPath
	}
	if relPath == "." {
		relPath = "<root>"
	}
	r.Failures = append(r.Failures, DirectoryFailure{
		Path:        relPath,
		Differences: differences,
	})
}

// Verifier handles verification operations
type Verifier struct {
	scanner *scanner.Scanner
}

// New creates a new Verifier instance
func New(sc *scanner.Scanner) *Verifier {
	return &Verifier{
		scanner: sc,
	}
}

// Verify recursively verifies manifest files starting from rootPath
func (v *Verifier) Verify(ctx context.Context, rootPath string) (*Result, error) {
	result := &Result{
		AllValid: true,
		Failures: make([]DirectoryFailure, 0),
	}

	err := v.scanner.Walk(ctx, rootPath, func(ctx context.Context, dirPath string, computedManifest *manifest.Manifest, cached bool, err error) error {
		if err != nil {
			return fmt.Errorf("failed to scan directory: %w", err)
		}
		if cached {
			result.ManifestSkipped++
			result.ManifestsFound++
			return nil
		}
		// Load existing manifest
		manifestPath := filepath.Join(dirPath, v.scanner.GetManifestName())
		existingManifest, loadErr := manifest.LoadManifest(manifestPath)
		if loadErr != nil {
			return fmt.Errorf("failed to load manifest for %s: %w", manifestPath, loadErr)
		}

		if existingManifest == nil {
			return fmt.Errorf("manifest in directory '%s' not found", dirPath)
		}

		result.ManifestsFound++

		// TODO(tjarosik): Here verify signature if needed

		// Compare manifests using the standalone function
		valid, differences, compareErr := manifest.CompareManifests(existingManifest, computedManifest)
		if compareErr != nil {
			return fmt.Errorf("failed to compare manifests for %s: %w", manifestPath, compareErr)
		}
		if !valid {
			result.ReportDirectoryFailure(rootPath, dirPath, differences)
			return nil
		}

		result.ManifestsVerified++
		// Touch the manifest to update its timestamp without changing content
		if touchErr := existingManifest.Touch(manifestPath); touchErr != nil {
			return fmt.Errorf("failed to touch manifest for %s: %w", manifestPath, touchErr)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	result.Stats = v.scanner.GetStats()

	return result, nil
}
