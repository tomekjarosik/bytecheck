package scanner

import (
	"context"
	"github.com/tomekjarosik/bytecheck/pkg/manifest"
	"github.com/tomekjarosik/bytecheck/pkg/traverse"
	"golang.org/x/sync/errgroup"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ScannedDirFunc func(ctx context.Context, dirPath string, m *manifest.Manifest, cached bool, err error) error

// Scanner handles file system scanning and checksum calculation
type Scanner struct {
	lastReportTime time.Time
	stats          Stats
	options        *options
	progressMutex  sync.Mutex
}

// New creates a new Scanner instance
func New(opts ...Option) *Scanner {
	return &Scanner{
		options: makeOptions(opts...),
	}
}

// Walk walks the file tree rooted at root, calling walkFn for each directory.
// It processes directories in POST-ORDER (children before parents) which is perfect
// for calculating directory checksums based on manifest files that depend on child manifests.
func (s *Scanner) Walk(ctx context.Context, root string, walkFn ScannedDirFunc) error {
	s.stats.Start(ctx, func(stats *Stats) {
		select {
		case <-ctx.Done():
			return
		case s.options.progressChannel <- stats:
		default: // channel is full, skip
		}
	}, 100*time.Millisecond)
	return traverse.WalkPostOrder(ctx, root, func(ctx context.Context, dirPath string, err error) error {
		if err != nil {
			return walkFn(ctx, dirPath, nil, false, err)
		}
		m, cached, err := s.scanDirectory(ctx, dirPath)
		return walkFn(ctx, dirPath, m, cached, err)
	})
}

func (s *Scanner) GetManifestName() string {
	return s.options.manifestName
}

func (s *Scanner) GetManifestFreshnessLimit() *time.Duration {
	return s.options.manifestFreshnessLimit
}

func (s *Scanner) GetProgressChannel() <-chan *Stats {
	return s.options.progressChannel
}

func (s *Scanner) scanDirectory(ctx context.Context, dir string) (m *manifest.Manifest, cached bool, err error) {
	// Check for fresh manifest first (same as before)
	m, err = manifest.LoadManifestIfFresh(
		filepath.Join(dir, s.options.manifestName),
		s.options.manifestFreshnessLimit)

	if err != nil {
		return nil, false, err
	}
	if m != nil {
		s.stats.IncreaseCachedProcessed()
		return m, true, nil
	}

	// Read and filter directory entries
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false, err
	}

	// Use channel-based worker pool
	type Job struct {
		index int
		entry os.DirEntry
	}

	type Result struct {
		index  int
		entity manifest.Entity
		err    error
	}

	jobs := make(chan Job)
	results := make(chan Result)

	// Determine worker count (you could make this configurable)
	workerCount := min(len(entries), s.options.workersCount)

	g, ctx := errgroup.WithContext(ctx)

	// Start workers
	for w := 0; w < workerCount; w++ {
		g.Go(func() error {
			for job := range jobs {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if job.entry.Name() == s.options.manifestName {
					continue
				}

				fullPath := filepath.Join(dir, job.entry.Name())
				if job.entry.IsDir() {
					fullPath = filepath.Join(fullPath, s.options.manifestName)
				}

				checksum, err := calculateChecksum(ctx, fullPath, &s.stats)
				if err != nil {
					return err
				}

				s.stats.IncreaseFilesProcessed()
				entity := manifest.Entity{
					Name:     job.entry.Name(),
					Checksum: checksum,
					IsDir:    job.entry.IsDir(),
				}
				results <- Result{index: job.index, entity: entity}
			}
			return nil
		})
	}

	// Send jobs
	g.Go(func() error {
		defer close(jobs)
		for i, entry := range entries {
			select {
			case jobs <- Job{index: i, entry: entry}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	go func() {
		g.Wait()
		close(results)
	}()

	computedEntities := make([]manifest.Entity, 0)
	var firstError error
	for result := range results {
		if result.err != nil && firstError == nil {
			firstError = result.err
		} else {
			computedEntities = append(computedEntities, result.entity)
		}
	}

	if err := g.Wait(); err != nil {
		return nil, false, err
	}
	if firstError != nil {
		return nil, false, firstError
	}

	s.stats.IncreaseDirProcessed()
	return manifest.New(computedEntities), false, nil
}

func (s *Scanner) GetStats() *Stats {
	return &s.stats
}
