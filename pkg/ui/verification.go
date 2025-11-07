package ui

import (
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"io"
)

// VerificationFailure represents a failed directory verification
type VerificationFailure struct {
	Path        string
	Differences []manifest.EntityDifference
}

// VerificationResult represents the result of a verification operation
type VerificationResult struct {
	ManifestsFound    int
	ManifestsVerified int
	ManifestsSkipped  int
	AllValid          bool
	Failures          []VerificationFailure
}

// PrintVerificationResult prints the verification result with appropriate colors and detailed differences
func PrintVerificationResult(w io.Writer, result *VerificationResult) {
	// Print failures with detailed information
	for _, failure := range result.Failures {
		fmt.Fprintf(w, "%s%s fail%s\n", ColorRed, failure.Path, ColorReset)
		PrintEntityDifferences(w, failure.Differences)
		fmt.Fprintln(w) // Empty line after each failed directory
	}

	// Print summary
	if result.ManifestsFound == 0 {
		fmt.Fprintf(w, "\n%sno manifests found%s\n", ColorYellow, ColorReset)
		return
	}

	if result.AllValid {
		fmt.Fprintf(w, "\n%sok%s - verified %d manifest(s) (%d skipped)\n", ColorGreen, ColorReset, result.ManifestsVerified, result.ManifestsSkipped)
	} else {
		fmt.Fprintf(w, "\n%sfailed%s - %d/%d manifests valid\n", ColorRed, ColorReset, result.ManifestsVerified, result.ManifestsFound)
	}
}

// ConvertVerificationResult converts from verify.Result to ui.VerificationResult
func ConvertVerificationResult(manifestsFound, manifestsVerified, manifestsSkipped int, allValid bool, failures []VerificationFailure) *VerificationResult {
	return &VerificationResult{
		ManifestsFound:    manifestsFound,
		ManifestsVerified: manifestsVerified,
		ManifestsSkipped:  manifestsSkipped,
		AllValid:          allValid,
		Failures:          failures,
	}
}
