package ui

import (
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"time"
)

// printProgress monitors the progress channel and prints updates
func PrintProgress(progressCh <-chan *scanner.Stats, quiet bool) {
	if quiet {
		// Just drain the channel without printing
		for range progressCh {
		}
		return
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var lastStats *scanner.Stats

	for {
		select {
		case stats, ok := <-progressCh:
			if !ok {
				// Channel closed, print final stats and return
				if lastStats != nil {
					clearProgressLine()
					elapsed := time.Since(lastStats.StartTime())
					fmt.Printf("%sfinal:%s %d files, %d dirs, %s bytes in %v\n",
						ColorGreen, ColorReset,
						lastStats.FilesProcessed(),
						lastStats.DirsProcessed(),
						formatBytes(lastStats.BytesProcessed()),
						elapsed.Round(time.Millisecond),
					)
				}
				return
			} else {
				lastStats = stats
			}

		case <-ticker.C:
			// Print periodic updates
			if lastStats != nil {
				elapsed := time.Since(lastStats.StartTime())
				rate := float64(lastStats.BytesProcessed()) / elapsed.Seconds()

				fmt.Printf("\r%sprogress:%s %8d files, %4d dirs, %s (%.1f MB/s) - %s",
					ColorCyan, ColorReset,
					lastStats.FilesProcessed(),
					lastStats.DirsProcessed(),
					formatBytes(lastStats.BytesProcessed()),
					rate/(1024*1024),
					truncatePath(lastStats.CurrentFile(), 50),
				)
			}
		}
	}
}

func clearProgressLine() {
	// Create a string of 120 spaces to overwrite the previous line
	spaces := make([]byte, 120)
	for i := range spaces {
		spaces[i] = ' '
	}
	fmt.Print("\r" + string(spaces) + "\r")
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-maxLen+3:]
}
