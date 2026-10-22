package engine

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Progress tracks and displays progress for long-running operations.
// It is TTY-aware: when stdout is not a TTY, it disables itself to avoid log spam.
type Progress struct {
	total     int
	completed int
	mu        sync.Mutex
	start     time.Time
	out       io.Writer
	isTTY     bool
	ticker    *time.Ticker
	done      chan struct{}
}

// NewProgress creates a new progress tracker.
func NewProgress(total int, out io.Writer, isTTY bool) *Progress {
	if out == nil {
		out = os.Stderr
	}
	return &Progress{
		total:     total,
		completed: 0,
		start:     time.Now(),
		out:       out,
		isTTY:     isTTY,
		done:      make(chan struct{}),
	}
}

// Increment adds one to the completed count.
func (p *Progress) Increment() {
	p.mu.Lock()
	p.completed++
	p.mu.Unlock()
}

// Add adds n to the completed count.
func (p *Progress) Add(n int) {
	p.mu.Lock()
	p.completed += n
	p.mu.Unlock()
}

// Start begins periodic progress updates (only if TTY).
func (p *Progress) Start(ctx context.Context) {
	if !p.isTTY {
		return
	}

	p.ticker = time.NewTicker(500 * time.Millisecond)
	go func() {
		defer p.ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.done:
				return
			case <-p.ticker.C:
				p.render()
			}
		}
	}()
}

// render prints the current progress.
func (p *Progress) render() {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.start).Round(time.Second)
	percent := 0
	if p.total > 0 {
		percent = (p.completed * 100) / p.total
	}

	// Calculate rate
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(p.completed) / elapsed.Seconds()
	}

	// Clear line and print progress
	fmt.Fprintf(p.out, "\r\033[K[%s] %d/%d (%d%%) | %.1f/s", elapsed, p.completed, p.total, percent, rate)
}

// Stop stops the progress updates and prints a final line.
func (p *Progress) Stop() {
	if !p.isTTY {
		return
	}

	close(p.done)
	if p.ticker != nil {
		p.ticker.Stop()
	}

	// Final render
	p.render()
	fmt.Fprintln(p.out) // Newline
}

// Summary returns a summary string.
func (p *Progress) Summary() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.start).Round(time.Second)
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(p.completed) / elapsed.Seconds()
	}

	return fmt.Sprintf("Completed %d tasks in %s (%.1f/s)", p.completed, elapsed, rate)
}

// IsTTY returns true if the output is a terminal.
func IsTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
