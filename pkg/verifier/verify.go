package verifier

import (
	"context"
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/issuer"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"path/filepath"
)

type ManifestVerificationStatus struct {
	Found   bool
	Skipped bool // because it was cached
	Valid   bool
	Signed  bool
	Audited bool
}

// DirectoryVerificationStatus DirectoryStatus represent verification status of each manifest thus directory
type DirectoryVerificationStatus struct {
	Path           string
	ManifestStatus ManifestVerificationStatus
	Differences    []manifest.EntityDifference
}

// Result represents the result of a verification operation
type Result struct {
	DirectoryStatuses []DirectoryVerificationStatus
	AuditorStatuses   map[issuer.Reference]issuer.Status
	Stats             *scanner.Stats
}

// Verifier handles verification operations
type Verifier struct {
	scanner       *scanner.Scanner
	auditor       ManifestAuditor
	trustVerifier issuer.Verifier
}

// New creates a new Verifier instance
func New(sc *scanner.Scanner, auditor ManifestAuditor, verifier issuer.Verifier) *Verifier {
	return &Verifier{
		scanner:       sc,
		auditor:       auditor,
		trustVerifier: verifier,
	}
}

// Verify recursively verifies manifest files starting from rootPath
func (v *Verifier) Verify(ctx context.Context, rootPath string) (*Result, error) {
	directoryStatuses := make([]DirectoryVerificationStatus, 0)

	err := v.scanner.Walk(ctx, rootPath, func(ctx context.Context, dirPath string, computedManifest *manifest.Manifest, cached bool, err error) error {
		if err != nil {
			return fmt.Errorf("failed to scan directory: %w", err)
		}
		dirStatus := DirectoryVerificationStatus{Path: dirPath}
		if cached {
			dirStatus.ManifestStatus = ManifestVerificationStatus{
				Found:   true,
				Skipped: true,
			}
			directoryStatuses = append(directoryStatuses, dirStatus)
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

		auditResult := v.auditor.Verify(existingManifest)
		if auditResult.IsAudited && auditResult.Error != nil {
			return fmt.Errorf("manifest audit failed for %s: %w", manifestPath, auditResult.Error)
		}

		// Compare manifests using the standalone function
		valid, differences, compareErr := manifest.CompareManifests(existingManifest, computedManifest)
		if compareErr != nil {
			return fmt.Errorf("failed to compare manifests for %s: %w", manifestPath, compareErr)
		}
		if !valid {
			dirStatus.ManifestStatus = ManifestVerificationStatus{
				Found:   true,
				Valid:   false,
				Signed:  auditResult.IsAudited,
				Audited: auditResult.IsAudited,
			}
			dirStatus.Differences = differences
			directoryStatuses = append(directoryStatuses, dirStatus)
			return nil
		}

		// Touch the manifest to update its timestamp without changing content
		if touchErr := existingManifest.Touch(manifestPath); touchErr != nil {
			return fmt.Errorf("failed to touch manifest for %s: %w", manifestPath, touchErr)
		}
		dirStatus.ManifestStatus = ManifestVerificationStatus{
			Found:   true,
			Valid:   true,
			Signed:  auditResult.IsAudited,
			Audited: auditResult.IsAudited}
		directoryStatuses = append(directoryStatuses, dirStatus)
		return nil
	})

	if err != nil {
		return nil, err
	}
	result := &Result{
		DirectoryStatuses: directoryStatuses,
		Stats:             v.scanner.GetStats(),
		AuditorStatuses:   v.trustVerifier.Verify(v.auditor.GetIssuers()),
	}

	return result, nil
}
