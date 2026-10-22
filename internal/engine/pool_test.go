package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolBasic(t *testing.T) {
	ctx := context.Background()
	pool := NewPool(ctx, 5)

	var processed int32
	pool.Start()

	// Submit some tasks
	for i := 0; i < 10; i++ {
		pool.Submit("task")
	}

	// Read results in a goroutine
	go func() {
		for range pool.Results() {
			atomic.AddInt32(&processed, 1)
		}
	}()

	pool.Wait()

	// Give results channel time to close
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&processed) != 10 {
		t.Errorf("expected 10 processed, got %d", processed)
	}
}

func TestPoolCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewPool(ctx, 3)

	var processed int32
	pool.Start()

	// Submit some tasks
	for i := 0; i < 100; i++ {
		pool.Submit("task")
	}

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// Read results
	go func() {
		for range pool.Results() {
			atomic.AddInt32(&processed, 1)
		}
	}()

	pool.Wait()

	// Should have processed some but not all
	processedCount := atomic.LoadInt32(&processed)
	if processedCount == 0 {
		t.Error("expected at least some tasks to be processed")
	}
	t.Logf("Processed %d tasks before cancellation", processedCount)
}

func TestProgressBasic(t *testing.T) {
	// Test with isTTY = false (should not output anything)
	progress := NewProgress(100, nil, false)

	progress.Start(context.Background())
	for i := 0; i < 50; i++ {
		progress.Increment()
	}
	progress.Stop()

	if progress.completed != 50 {
		t.Errorf("expected 50 completed, got %d", progress.completed)
	}
}

func TestProgressAdd(t *testing.T) {
	progress := NewProgress(100, nil, false)

	progress.Add(10)
	progress.Add(5)

	if progress.completed != 15 {
		t.Errorf("expected 15 completed, got %d", progress.completed)
	}
}

func TestProgressSummary(t *testing.T) {
	progress := NewProgress(100, nil, false)
	progress.completed = 50

	summary := progress.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
	t.Logf("Summary: %s", summary)
}
