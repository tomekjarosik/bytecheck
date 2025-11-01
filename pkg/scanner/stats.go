package scanner

import (
	"sync/atomic"
	"time"
)

// Stats contains statistics about the scanning progress
type Stats struct {
	BytesProcessed  int64     // Total bytes read and checksummed
	FilesProcessed  int64     // Number of files processed
	CachedProcessed int64     // Number of manifests read from a file (cached)
	DirsProcessed   int64     // Number of directories processed
	CurrentFile     string    // Currently processing file (if any)
	StartTime       time.Time // When scanning started
	LastReportTime  time.Time // When this report was generated
}

func (s *Stats) Clear() {
	atomic.StoreInt64(&s.BytesProcessed, 0)
	atomic.StoreInt64(&s.FilesProcessed, 0)
	atomic.StoreInt64(&s.DirsProcessed, 0)

	s.CurrentFile = ""
	s.StartTime = time.Time{}
	s.LastReportTime = time.Time{}
}

func (s *Stats) Start() {
	s.Clear()
	s.StartTime = time.Now()
}

func (s *Stats) IncreaseDirProcessed() {
	atomic.AddInt64(&s.DirsProcessed, 1)
}

func (s *Stats) IncreaseFilesProcessed() {
	atomic.AddInt64(&s.FilesProcessed, 1)
}

func (s *Stats) IncreaseCachedProcessed() {
	atomic.AddInt64(&s.CachedProcessed, 1)
}

func (s *Stats) AddBytesProcessed(bytes int64) {
	atomic.AddInt64(&s.BytesProcessed, bytes)
}
