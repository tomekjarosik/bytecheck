package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStats_Clear(t *testing.T) {
	stats := &Stats{}

	// Set some values first
	atomic.StoreInt64(&stats.bytesProcessed, 100)
	atomic.StoreInt64(&stats.filesProcessed, 10)
	atomic.StoreInt64(&stats.cachedProcessed, 5)
	atomic.StoreInt64(&stats.dirsProcessed, 3)
	stats.SetCurrentFile("test.txt")
	stats.mu.Lock()
	stats.startTime = time.Now()
	stats.mu.Unlock()

	// Clear and verify
	stats.Clear()

	if stats.BytesProcessed() != 0 {
		t.Errorf("Expected BytesProcessed to be 0, got %d", stats.BytesProcessed())
	}
	if stats.FilesProcessed() != 0 {
		t.Errorf("Expected FilesProcessed to be 0, got %d", stats.FilesProcessed())
	}
	if stats.CachedProcessed() != 0 {
		t.Errorf("Expected CachedProcessed to be 0, got %d", stats.CachedProcessed())
	}
	if stats.DirsProcessed() != 0 {
		t.Errorf("Expected DirsProcessed to be 0, got %d", stats.DirsProcessed())
	}
	if stats.CurrentFile() != "" {
		t.Errorf("Expected CurrentFile to be empty, got %s", stats.CurrentFile())
	}
	if !stats.StartTime().IsZero() {
		t.Errorf("Expected StartTime to be zero, got %v", stats.StartTime())
	}
}

func TestStats_Getters(t *testing.T) {
	stats := &Stats{}

	// Test atomic getters
	atomic.StoreInt64(&stats.bytesProcessed, 1024)
	atomic.StoreInt64(&stats.filesProcessed, 42)
	atomic.StoreInt64(&stats.cachedProcessed, 7)
	atomic.StoreInt64(&stats.dirsProcessed, 3)

	if stats.BytesProcessed() != 1024 {
		t.Errorf("Expected BytesProcessed to be 1024, got %d", stats.BytesProcessed())
	}
	if stats.FilesProcessed() != 42 {
		t.Errorf("Expected FilesProcessed to be 42, got %d", stats.FilesProcessed())
	}
	if stats.CachedProcessed() != 7 {
		t.Errorf("Expected CachedProcessed to be 7, got %d", stats.CachedProcessed())
	}
	if stats.DirsProcessed() != 3 {
		t.Errorf("Expected DirsProcessed to be 3, got %d", stats.DirsProcessed())
	}
}

func TestStats_SetAndGetCurrentFile(t *testing.T) {
	stats := &Stats{}
	testFile := "test/file.txt"

	stats.SetCurrentFile(testFile)

	if stats.CurrentFile() != testFile {
		t.Errorf("Expected CurrentFile to be %s, got %s", testFile, stats.CurrentFile())
	}
}

func TestStats_Snapshot(t *testing.T) {
	stats := &Stats{}
	now := time.Now()

	// Set up test data
	atomic.StoreInt64(&stats.bytesProcessed, 2048)
	atomic.StoreInt64(&stats.filesProcessed, 20)
	atomic.StoreInt64(&stats.cachedProcessed, 5)
	atomic.StoreInt64(&stats.dirsProcessed, 2)
	stats.SetCurrentFile("snapshot_test.txt")
	stats.mu.Lock()
	stats.startTime = now
	stats.mu.Unlock()

	snapshot := stats.Snapshot()

	if snapshot.BytesProcessed() != 2048 {
		t.Errorf("Expected snapshot BytesProcessed to be 2048, got %d", snapshot.BytesProcessed())
	}
	if snapshot.FilesProcessed() != 20 {
		t.Errorf("Expected snapshot FilesProcessed to be 20, got %d", snapshot.FilesProcessed())
	}
	if snapshot.CachedProcessed() != 5 {
		t.Errorf("Expected snapshot CachedProcessed to be 5, got %d", snapshot.CachedProcessed())
	}
	if snapshot.DirsProcessed() != 2 {
		t.Errorf("Expected snapshot DirsProcessed to be 2, got %d", snapshot.DirsProcessed())
	}
	if snapshot.CurrentFile() != "snapshot_test.txt" {
		t.Errorf("Expected snapshot CurrentFile to be 'snapshot_test.txt', got %s", snapshot.CurrentFile())
	}
	if !snapshot.StartTime().Equal(now) {
		t.Errorf("Expected snapshot StartTime to be %v, got %v", now, snapshot.StartTime())
	}
}

func TestStats_IncrementMethods(t *testing.T) {
	stats := &Stats{}

	// Test increment methods
	stats.IncreaseDirProcessed()
	stats.IncreaseDirProcessed()
	if stats.DirsProcessed() != 2 {
		t.Errorf("Expected DirsProcessed to be 2, got %d", stats.DirsProcessed())
	}

	stats.IncreaseFilesProcessed()
	stats.IncreaseFilesProcessed()
	stats.IncreaseFilesProcessed()
	if stats.FilesProcessed() != 3 {
		t.Errorf("Expected FilesProcessed to be 3, got %d", stats.FilesProcessed())
	}

	stats.IncreaseCachedProcessed()
	if stats.CachedProcessed() != 1 {
		t.Errorf("Expected CachedProcessed to be 1, got %d", stats.CachedProcessed())
	}
}

func TestStats_AddBytesProcessed(t *testing.T) {
	stats := &Stats{}

	stats.AddBytesProcessed(1024)
	stats.AddBytesProcessed(512)

	if stats.BytesProcessed() != 1536 {
		t.Errorf("Expected BytesProcessed to be 1536, got %d", stats.BytesProcessed())
	}
}

func TestStats_Start_CallbackTriggered(t *testing.T) {
	stats := &Stats{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var callbackCount int32
	var lastSnapshot *Stats
	var mu sync.Mutex

	callback := func(s *Stats) {
		mu.Lock()
		defer mu.Unlock()
		atomic.AddInt32(&callbackCount, 1)
		snapshot := *s
		lastSnapshot = &snapshot
	}

	beforeStart := time.Now()
	stats.Start(ctx, callback, 2*time.Millisecond)

	// Initial callback should be triggered immediately
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	if lastSnapshot == nil {
		t.Fatal("Expected initial callback to be triggered")
	}
	if lastSnapshot.StartTime().Before(beforeStart) {
		t.Errorf("Expected StartTime to be set correctly")
	}
	mu.Unlock()

	// Make some changes to trigger updates
	stats.IncreaseFilesProcessed()
	stats.AddBytesProcessed(1024)

	// Wait for periodic update
	time.Sleep(5 * time.Millisecond)

	finalCount := atomic.LoadInt32(&callbackCount)
	if finalCount < 2 {
		t.Errorf("Expected at least 2 callbacks, got %d", finalCount)
	}

	cancel() // Stop the goroutine
}

func TestStats_PeriodicUpdates(t *testing.T) {
	stats := &Stats{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var updateCount int32
	callback := func(s *Stats) {
		atomic.AddInt32(&updateCount, 1)
	}

	stats.Start(ctx, callback, 2*time.Millisecond)

	// Make changes to mark as dirty
	stats.IncreaseFilesProcessed()
	stats.IncreaseDirProcessed()

	// Wait for multiple update cycles
	time.Sleep(10 * time.Millisecond)

	count := atomic.LoadInt32(&updateCount)
	if count < 2 {
		t.Errorf("Expected at least 2 periodic updates, got %d", count)
	}

	cancel()
}

func TestStats_ConcurrentAccess(t *testing.T) {
	stats := &Stats{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var updateCount int32
	callback := func(s *Stats) {
		atomic.AddInt32(&updateCount, 1)
	}

	stats.Start(ctx, callback, 1*time.Millisecond)

	// Run concurrent operations
	var wg sync.WaitGroup
	numGoroutines := 10
	operationsPerGoroutine := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				stats.IncreaseFilesProcessed()
				stats.AddBytesProcessed(int64(j))
				stats.IncreaseDirProcessed()
				stats.IncreaseCachedProcessed()
				stats.SetCurrentFile(fmt.Sprintf("file_%d_%d", id, j))
			}
		}(i)
	}

	wg.Wait()

	// Verify final counts
	expectedFiles := int64(numGoroutines * operationsPerGoroutine)
	expectedDirs := int64(numGoroutines * operationsPerGoroutine)
	expectedCached := int64(numGoroutines * operationsPerGoroutine)

	if stats.FilesProcessed() != expectedFiles {
		t.Errorf("Expected FilesProcessed to be %d, got %d", expectedFiles, stats.FilesProcessed())
	}
	if stats.DirsProcessed() != expectedDirs {
		t.Errorf("Expected DirsProcessed to be %d, got %d", expectedDirs, stats.DirsProcessed())
	}
	if stats.CachedProcessed() != expectedCached {
		t.Errorf("Expected CachedProcessed to be %d, got %d", expectedCached, stats.CachedProcessed())
	}

	// Check that bytes were accumulated correctly
	var expectedBytes int64
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < operationsPerGoroutine; j++ {
			expectedBytes += int64(j)
		}
	}
	if stats.BytesProcessed() != expectedBytes {
		t.Errorf("Expected BytesProcessed to be %d, got %d", expectedBytes, stats.BytesProcessed())
	}

	cancel()
}

func TestStats_DirtyFlag(t *testing.T) {
	stats := &Stats{}

	// Initially, dirty flag should be 0
	if atomic.LoadInt32(&stats.dirty) != 0 {
		t.Errorf("Expected dirty flag to be 0 initially, got %d", atomic.LoadInt32(&stats.dirty))
	}

	// After calling requestUpdate, dirty flag should be 1
	stats.requestUpdate()
	if atomic.LoadInt32(&stats.dirty) != 1 {
		t.Errorf("Expected dirty flag to be 1 after requestUpdate, got %d", atomic.LoadInt32(&stats.dirty))
	}
}

func TestStats_NoCallback(t *testing.T) {
	stats := &Stats{}

	// Test that sendUpdate doesn't panic when onUpdate is nil
	stats.sendUpdate()

	// Test that operations work without callback
	stats.IncreaseFilesProcessed()
	stats.AddBytesProcessed(100)

	if stats.FilesProcessed() != 1 {
		t.Errorf("Expected FilesProcessed to be 1, got %d", stats.FilesProcessed())
	}
	if stats.BytesProcessed() != 100 {
		t.Errorf("Expected BytesProcessed to be 100, got %d", stats.BytesProcessed())
	}
}

func TestStats_ContextCancellation(t *testing.T) {
	stats := &Stats{}
	ctx, cancel := context.WithCancel(context.Background())

	var callbackCount int32
	callback := func(s *Stats) {
		atomic.AddInt32(&callbackCount, 1)
	}

	stats.Start(ctx, callback, 2*time.Millisecond)

	// Wait a bit to ensure the goroutine is running
	time.Sleep(5 * time.Millisecond)

	// Cancel context
	cancel()

	// Wait for goroutine to stop
	time.Sleep(5 * time.Millisecond)

	// Make changes - should still mark as dirty but not trigger updates
	beforeCount := atomic.LoadInt32(&callbackCount)
	stats.IncreaseFilesProcessed()

	// Wait longer than update interval
	time.Sleep(5 * time.Millisecond)

	afterCount := atomic.LoadInt32(&callbackCount)

	// Should not have additional callbacks after context cancellation
	if afterCount != beforeCount {
		t.Errorf("Expected no new callbacks after context cancellation, before: %d, after: %d", beforeCount, afterCount)
	}
}

func TestStats_Stop(t *testing.T) {
	stats := &Stats{}
	var callbackCount int32

	callback := func(s *Stats) {
		atomic.AddInt32(&callbackCount, 1)
	}

	stats.onUpdate = callback

	beforeCount := atomic.LoadInt32(&callbackCount)
	stats.Stop()
	afterCount := atomic.LoadInt32(&callbackCount)

	if afterCount != beforeCount+1 {
		t.Errorf("Expected Stop to trigger one callback, before: %d, after: %d", beforeCount, afterCount)
	}
}
