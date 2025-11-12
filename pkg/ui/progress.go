package ui

import (
	"context"
	"fmt"
	"github.com/tomekjarosik/bytecheck/pkg/scanner"
	"io"
	"time"
)

// ProgressMonitor manages both instantaneous and average speed calculations
type ProgressMonitor struct {
	recentSamples []speedSample
	windowSize    time.Duration
	lastStats     *scanner.Stats
	done          chan bool
}

type speedSample struct {
	timestamp time.Time
	bytes     int64
}

// NewProgressMonitor creates a new progress monitor with the specified window size
func NewProgressMonitor(windowSize time.Duration) *ProgressMonitor {
	return &ProgressMonitor{
		recentSamples: make([]speedSample, 0),
		windowSize:    windowSize,
	}
}

// AddSample adds a new speed sample to the monitor
func (pm *ProgressMonitor) AddSample(stats *scanner.Stats) {
	pm.lastStats = stats

	sample := speedSample{
		timestamp: time.Now(),
		bytes:     stats.BytesProcessed(),
	}

	pm.recentSamples = append(pm.recentSamples, sample)

	// Remove samples outside our time window
	pm.cleanOldSamples()
}

// cleanOldSamples removes samples older than the window size
func (pm *ProgressMonitor) cleanOldSamples() {
	cutoff := time.Now().Add(-pm.windowSize)
	i := 0
	for i < len(pm.recentSamples) {
		if pm.recentSamples[i].timestamp.After(cutoff) {
			break
		}
		i++
	}
	pm.recentSamples = pm.recentSamples[i:]
}

// InstantaneousSpeed calculates the speed over the recent window
func (pm *ProgressMonitor) InstantaneousSpeed() float64 {
	if len(pm.recentSamples) < 2 {
		return 0
	}

	oldest := pm.recentSamples[0]
	newest := pm.recentSamples[len(pm.recentSamples)-1]

	timeDiff := newest.timestamp.Sub(oldest.timestamp).Seconds()
	if timeDiff <= 0 {
		return 0
	}

	bytesDiff := newest.bytes - oldest.bytes
	return float64(bytesDiff) / timeDiff
}

// AverageSpeed calculates the overall average speed
func (pm *ProgressMonitor) AverageSpeed(stats *scanner.Stats) float64 {
	elapsed := time.Since(stats.StartTime()).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(stats.BytesProcessed()) / elapsed
}

// Monitor monitors the progress channel and prints updates
func (pm *ProgressMonitor) Monitor(ctx context.Context, w io.Writer, progressCh <-chan *scanner.Stats) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	var lastStats *scanner.Stats

	for {
		select {
		case <-ctx.Done():
			return
		case stats, ok := <-progressCh:
			if !ok {
				return
			}
			lastStats = stats
			pm.AddSample(stats)

		case <-ticker.C:
			if lastStats != nil {
				pm.PrintProgressLine(w, lastStats)
			}
		}
	}
}

func (pm *ProgressMonitor) MonitorInBackground(ctx context.Context, w io.Writer, progressCh <-chan *scanner.Stats) {
	pm.done = make(chan bool)
	go func() {
		pm.Monitor(ctx, w, progressCh)
		pm.done <- true
	}()
}

func (pm *ProgressMonitor) Wait() {
	<-pm.done
}

// PrintProgressLine prints a progress line with both instantaneous and average speeds
func (pm *ProgressMonitor) PrintProgressLine(w io.Writer, stats *scanner.Stats) {
	// TODO: elapsed := time.Since(stats.StartTime())

	// Calculate both speeds
	instantRate := pm.InstantaneousSpeed()
	averageRate := pm.AverageSpeed(stats)

	clearProgressLine(w)

	// Show both speeds: instantaneous (last 3s) and overall average
	fmt.Fprintf(w, "\r%sprogress:%s %8d files, %4d dirs, %s, speed: %.1f MB/s (avg: %.1f MB/s) - %s",
		ColorCyan, ColorReset,
		stats.FilesProcessed(),
		stats.DirsProcessed(),
		formatBytes(stats.BytesProcessed()),
		instantRate/(1024*1024),
		averageRate/(1024*1024),
		truncatePath(stats.CurrentFile(), 50))
}

// PrintFinalLine prints a progress line with both instantaneous and average speeds
func (pm *ProgressMonitor) PrintFinalLine(w io.Writer, stats *scanner.Stats) {
	elapsed := time.Since(stats.StartTime())

	averageRate := pm.AverageSpeed(stats)

	clearProgressLine(w)

	fmt.Fprintf(w, "\r%sfinal:%s %8d files, %4d dirs, %s, speed: %.1f MB/s over %.1f seconds - %s\n",
		ColorCyan, ColorReset,
		stats.FilesProcessed(),
		stats.DirsProcessed(),
		formatBytes(stats.BytesProcessed()),
		averageRate/(1024*1024),
		elapsed.Seconds(),
		truncatePath(stats.CurrentFile(), 50))
}

func clearProgressLine(w io.Writer) {
	// Create a string of 120 spaces to overwrite the previous line
	spaces := make([]byte, 120)
	for i := range spaces {
		spaces[i] = ' '
	}
	fmt.Fprint(w, "\r"+string(spaces)+"\r")
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
