package ui

import (
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"io"
	"time"
)

// ANSI color codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

// OutputOptions controls output behavior
type OutputOptions struct {
	Verbose bool
	Quiet   bool
}

// ProgressTracker handles progress reporting for long-running operations
type ProgressTracker struct {
	lastProgressTime time.Time
	progressInterval time.Duration
	quiet            bool
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(quiet bool) *ProgressTracker {
	return &ProgressTracker{
		lastProgressTime: time.Now(),
		progressInterval: 2 * time.Second,
		quiet:            quiet,
	}
}

// ShowProgress displays progress if enough time has elapsed
func (pt *ProgressTracker) ShowProgress(processed, skipped int) {
	if pt.quiet || time.Since(pt.lastProgressTime) < pt.progressInterval {
		return
	}

	fmt.Printf("\r%sprogress:%s processed %d, skipped %d directories...",
		ColorCyan, ColorReset, processed, skipped)
	pt.lastProgressTime = time.Now()
}

// ClearProgress clears the progress line
func (pt *ProgressTracker) ClearProgress(startTime time.Time) {
	if !pt.quiet && time.Since(startTime) > pt.progressInterval {
		fmt.Print("\r" + string(make([]byte, 60)) + "\r") // Clear the progress line
	}
}

// Pluralize returns the singular or plural form based on count
func Pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// PrintSuccess prints a success message with green color
func PrintSuccess(format string, args ...interface{}) {
	fmt.Printf("%sok%s - "+format+"\n", append([]interface{}{ColorGreen, ColorReset}, args...)...)
}

// PrintWarning prints a warning message with yellow color
func PrintWarning(format string, args ...interface{}) {
	fmt.Printf("%swarning%s - "+format+"\n", append([]interface{}{ColorYellow, ColorReset}, args...)...)
}

// PrintError prints an error message with red color
func PrintError(format string, args ...interface{}) {
	fmt.Printf("%serror%s - "+format+"\n", append([]interface{}{ColorRed, ColorReset}, args...)...)
}

// PrintEntityDifferences prints detailed differences for manifest entities
func PrintEntityDifferences(w io.Writer, differences []manifest.EntityDifference) {
	for _, diff := range differences {
		switch diff.Type {
		case manifest.DiffMissingInB:
			entityType := "file"
			if diff.ExpectedEntity != nil && diff.ExpectedEntity.IsDir {
				entityType = "directory"
			}
			fmt.Fprintf(w, "  %s- missing %s:%s %s\n", ColorRed, entityType, ColorReset, diff.Name)

		case manifest.DiffMissingInA:
			entityType := "file"
			if diff.ActualEntity != nil && diff.ActualEntity.IsDir {
				entityType = "directory"
			}
			fmt.Fprintf(w, "  %s+ extra %s:%s %s\n", ColorYellow, entityType, ColorReset, diff.Name)

		case manifest.DiffTypeMismatch:
			expectedType := "file"
			actualType := "file"
			if diff.ExpectedEntity != nil && diff.ExpectedEntity.IsDir {
				expectedType = "directory"
			}
			if diff.ActualEntity != nil && diff.ActualEntity.IsDir {
				actualType = "directory"
			}
			fmt.Fprintf(w, "  %s~ type mismatch:%s %s (expected %s, got %s)\n",
				ColorCyan, ColorReset, diff.Name, expectedType, actualType)

		case manifest.DiffChecksumMismatch:
			entityType := "file"
			if diff.ExpectedEntity != nil && diff.ExpectedEntity.IsDir {
				entityType = "directory"
			}
			fmt.Fprintf(w, "  %s! checksum mismatch:%s %s (%s)\n",
				ColorCyan, ColorReset, diff.Name, entityType)

			if diff.ExpectedEntity != nil && diff.ActualEntity != nil {
				fmt.Fprintf(w, "    expected: %s\n", diff.ExpectedEntity.Checksum)
				fmt.Fprintf(w, "    actual:   %s\n", diff.ActualEntity.Checksum)
			}
		}
	}
}
