// Package engine provides bounded worker pool and result streaming.
package engine

import (
	"context"
	"sync"
)

// Task is a unit of work to be processed by workers.
type Task struct {
	Target string
}

// Result is the output of processing a task.
type Result struct {
	Target string
	Error  error
}

// Pool is a bounded worker pool with context-based shutdown.
type Pool struct {
	numWorkers     int
	tasks          chan Task
	results        chan Result
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	closeTasksOnce sync.Once
	closeResOnce   sync.Once
}

// NewPool creates a new worker pool with the given number of workers.
func NewPool(ctx context.Context, numWorkers int) *Pool {
	// Create a cancellable context
	ctx, cancel := context.WithCancel(ctx)

	// Buffer sizes: both buffered to avoid deadlocks
	taskBufferSize := numWorkers * 2
	resultBufferSize := numWorkers * 2

	return &Pool{
		numWorkers: numWorkers,
		tasks:      make(chan Task, taskBufferSize),
		results:    make(chan Result, resultBufferSize),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start begins the worker goroutines.
func (p *Pool) Start() {
	for i := 0; i < p.numWorkers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.worker()
		}()
	}
}

// worker is the main worker loop that processes tasks.
func (p *Pool) worker() {
	for {
		select {
		case <-p.ctx.Done():
			// Context cancelled, drain remaining tasks
			for {
				select {
				case _, ok := <-p.tasks:
					if !ok {
						return // Channel closed, exit
					}
				default:
					return // Context done, exit
				}
			}
		case task, ok := <-p.tasks:
			if !ok {
				// Tasks channel closed, worker done
				return
			}
			// Process the task
			result := Result{Target: task.Target}
			select {
			case <-p.ctx.Done():
				return
			case p.results <- result:
			}
		}
	}
}

// Submit adds a task to the pool.
func (p *Pool) Submit(target string) {
	select {
	case <-p.ctx.Done():
		// Pool is shutting down
	case p.tasks <- Task{Target: target}:
	}
}

// Close closes the tasks channel, signaling workers to finish.
func (p *Pool) Close() {
	p.closeTasksOnce.Do(func() {
		close(p.tasks)
	})
}

// Wait blocks until all workers have finished.
func (p *Pool) Wait() {
	p.Close()
	p.wg.Wait()
	p.closeResOnce.Do(func() {
		close(p.results)
	})
}

// Results returns the results channel for reading processed results.
func (p *Pool) Results() <-chan Result {
	return p.results
}

// Cancel cancels the context, initiating shutdown.
func (p *Pool) Cancel() {
	p.cancel()
}

// Process runs the pool with a handler function.
// The handler returns the result and any error.
func (p *Pool) Process(handler func(context.Context, Task) (Result, error)) error {
	p.Start()

	// Start a goroutine to run the handler for each task
	go func() {
		defer p.closeResOnce.Do(func() {
			close(p.results)
		})
		for {
			select {
			case <-p.ctx.Done():
				return
			case task, ok := <-p.tasks:
				if !ok {
					return
				}
				result, err := handler(p.ctx, task)
				if err != nil {
					result = Result{Target: task.Target, Error: err}
				}
				select {
				case <-p.ctx.Done():
					return
				case p.results <- result:
				}
			}
		}
	}()

	return nil
}

// DrainResults reads all results from the pool.
func DrainResults(ctx context.Context, results <-chan Result, callback func(Result)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				return nil // Channel closed, all done
			}
			callback(result)
		}
	}
}
