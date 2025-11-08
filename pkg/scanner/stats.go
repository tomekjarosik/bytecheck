package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Stats contains statistics about the scanning progress
type Stats struct {
	// Atomic fields (must be 64-bit aligned on 32-bit systems)
	bytesProcessed  int64
	filesProcessed  int64
	cachedProcessed int64
	dirsProcessed   int64

	// Protected by mutex
	mu          sync.RWMutex
	currentFile string
	startTime   time.Time

	dirty    int32 // Atomic dirty flag
	onUpdate func(*Stats)
}

func (s *Stats) Clear() {
	atomic.StoreInt64(&s.bytesProcessed, 0)
	atomic.StoreInt64(&s.filesProcessed, 0)
	atomic.StoreInt64(&s.cachedProcessed, 0)
	atomic.StoreInt64(&s.dirsProcessed, 0)

	s.mu.Lock()
	s.currentFile = ""
	s.startTime = time.Time{}
	s.mu.Unlock()
}

func (s *Stats) Snapshot() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return Stats{
		bytesProcessed:  atomic.LoadInt64(&s.bytesProcessed),
		filesProcessed:  atomic.LoadInt64(&s.filesProcessed),
		cachedProcessed: atomic.LoadInt64(&s.cachedProcessed),
		dirsProcessed:   atomic.LoadInt64(&s.dirsProcessed),
		currentFile:     s.currentFile,
		startTime:       s.startTime,
	}
}

func (s *Stats) BytesProcessed() int64  { return atomic.LoadInt64(&s.bytesProcessed) }
func (s *Stats) FilesProcessed() int64  { return atomic.LoadInt64(&s.filesProcessed) }
func (s *Stats) CachedProcessed() int64 { return atomic.LoadInt64(&s.cachedProcessed) }
func (s *Stats) DirsProcessed() int64   { return atomic.LoadInt64(&s.dirsProcessed) }
func (s *Stats) StartTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.startTime
}
func (s *Stats) CurrentFile() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentFile
}

func (s *Stats) SetCurrentFile(currentFile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentFile = currentFile
}

func (s *Stats) Start(ctx context.Context, onUpdate func(*Stats), updateInterval time.Duration) {
	s.Clear()
	s.mu.Lock()
	s.startTime = time.Now()
	s.onUpdate = onUpdate
	s.mu.Unlock()

	s.sendUpdate()

	// Periodic batch updates
	go func() {
		ticker := time.NewTicker(updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if atomic.CompareAndSwapInt32(&s.dirty, 1, 0) {
					s.sendUpdate()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Stats) IncreaseDirProcessed() {
	atomic.AddInt64(&s.dirsProcessed, 1)
	s.requestUpdate()
}

func (s *Stats) IncreaseFilesProcessed() {
	atomic.AddInt64(&s.filesProcessed, 1)
	s.requestUpdate()
}

func (s *Stats) IncreaseCachedProcessed() {
	atomic.AddInt64(&s.cachedProcessed, 1)
	s.requestUpdate()
}

func (s *Stats) AddBytesProcessed(bytes int64) {
	atomic.AddInt64(&s.bytesProcessed, bytes)
	s.requestUpdate()
}

func (s *Stats) requestUpdate() {
	atomic.StoreInt32(&s.dirty, 1)
}

func (s *Stats) sendUpdate() {
	if s.onUpdate == nil {
		return
	}

	snapshot := s.Snapshot()
	s.onUpdate(&snapshot)
}
