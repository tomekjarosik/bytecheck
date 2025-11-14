package ui

import (
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/trust"
	"github.com/tomekjarosik/bytecheck/pkg/verifier"
	"io"
	"strings"
)

// PrintVerificationResult prints the verification result with appropriate colors and detailed differences
func PrintVerificationResult(w io.Writer, result *verifier.Result) {
	// Print failures with detailed information
	allValid := true
	manifestsFound := 0
	manifestsVerified := 0
	manifestsSkipped := 0
	for _, status := range result.DirectoryStatuses {
		if status.ManifestStatus.Found {
			manifestsFound++
		}
		if status.ManifestStatus.Skipped {
			manifestsSkipped++
			continue
		}
		if !status.ManifestStatus.Valid {
			fmt.Fprintf(w, "%s%s fail%s\n", ColorRed, status.Path, ColorReset)
			PrintEntityDifferences(w, status.Differences)
			fmt.Fprintln(w) // Empty line after each failed directory
			allValid = false
		}
		if status.ManifestStatus.Valid {
			manifestsVerified++
		}

	}

	// Print auditor statuses
	printAuditorStatuses(w, result.AuditorStatuses)

	// Print summary
	if manifestsFound == 0 {
		fmt.Fprintf(w, "\n%sno manifests found%s\n", ColorYellow, ColorReset)
		return
	}

	if allValid {
		fmt.Fprintf(w, "\n%sok%s - verified %d manifest(s) (%d skipped)\n", ColorGreen, ColorReset, manifestsVerified, manifestsSkipped)
	} else {
		fmt.Fprintf(w, "\n%sfailed%s - %d/%d manifests valid\n", ColorRed, ColorReset, manifestsVerified, manifestsFound)
	}
}

// Enhanced printAuditorStatuses with fishy detection
func printAuditorStatuses(w io.Writer, auditorStatuses map[trust.IssuerReference]trust.IssuerStatus) {
	if len(auditorStatuses) == 0 {
		fmt.Fprintf(w, "\n%sAuditors: none%s\n", ColorYellow, ColorReset)
		return
	}

	// Track counts for summary
	trustedCount := 0
	fishyCount := 0
	unsupportedCount := 0
	errorCount := 0

	for ref, status := range auditorStatuses {
		var statusText string
		var color string

		switch {
		case !status.Supported:
			statusText = "unsupported"
			color = ColorYellow
			unsupportedCount++
		case status.Error != nil:
			if isFishyError(status.Error) {
				statusText = fmt.Sprintf("fishy: %s", status.Error)
				color = ColorYellow
				fishyCount++
			} else {
				statusText = fmt.Sprintf("error: %s", status.Error)
				color = ColorRed
				errorCount++
			}
		case status.Supported && status.Error == nil:
			statusText = "trusted"
			color = ColorGreen
			trustedCount++
		default:
			statusText = "unknown"
			color = ColorYellow
		}

		fmt.Fprintf(w, "audited by %s%s%s %s[%s]%s\n",
			ColorCyan, ref, ColorReset,
			color, statusText, ColorReset)
	}

	//// Print auditor summary (same as before)
	//summaryParts := []string{}
	//if trustedCount > 0 {
	//	summaryParts = append(summaryParts, fmt.Sprintf("%s%d trusted%s", ColorGreen, trustedCount, ColorReset))
	//}
	//if fishyCount > 0 {
	//	summaryParts = append(summaryParts, fmt.Sprintf("%s%d fishy%s", ColorYellow, fishyCount, ColorReset))
	//}
	//if unsupportedCount > 0 {
	//	summaryParts = append(summaryParts, fmt.Sprintf("%s%d unsupported%s", ColorYellow, unsupportedCount, ColorReset))
	//}
	//if errorCount > 0 {
	//	summaryParts = append(summaryParts, fmt.Sprintf("%s%d with errors%s", ColorRed, errorCount, ColorReset))
	//}
	//
	//if len(summaryParts) > 0 {
	//	fmt.Fprintf(w, "auditors: %s\n", strings.Join(summaryParts, ", "))
	//}
}

// isFishyError determines if an error represents a "fishy" situation rather than a hard failure
func isFishyError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	// Consider errors related to key validation as "fishy" rather than complete failures
	fishyIndicators := []string{
		"key expired",
		"not found in trusted source",
		"validation warning",
		"fishy",
		"questionable",
	}

	for _, indicator := range fishyIndicators {
		if strings.Contains(strings.ToLower(errStr), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}
