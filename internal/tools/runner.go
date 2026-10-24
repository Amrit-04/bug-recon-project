package tools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

// CommandRunner defines the interface for running external commands in a testable manner.
type CommandRunner interface {
	Run(ctx context.Context, bin string, args []string, stdin io.Reader) (stdout, stderr []byte, err error)
	LookPath(bin string) (string, error)
}

// ExecRunner is the production implementation of CommandRunner backed by os/exec.
type ExecRunner struct{}

// NewExecRunner returns a new ExecRunner.
func NewExecRunner() *ExecRunner {
	return &ExecRunner{}
}

// Run executes the specified binary with arguments, feeding stdin and capturing stdout/stderr.
func (e *ExecRunner) Run(ctx context.Context, bin string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	return stdoutBuf.Bytes(), stderrBuf.Bytes(), err
}

// LookPath checks if the binary exists on PATH.
func (e *ExecRunner) LookPath(bin string) (string, error) {
	return exec.LookPath(bin)
}

// MockHandler defines a function that handles mock command execution.
type MockHandler func(ctx context.Context, args []string, stdin []byte) (stdout, stderr []byte, err error)

// MockCall records an invocation of Run on MockRunner.
type MockCall struct {
	Bin   string
	Args  []string
	Stdin []byte
}

// MockRunner is an in-memory implementation of CommandRunner for deterministic unit tests.
type MockRunner struct {
	mu        sync.Mutex
	Installed map[string]string      // bin -> resolved path
	Handlers  map[string]MockHandler // bin -> handler
	Calls     []MockCall
}

// NewMockRunner returns a new initialized MockRunner.
func NewMockRunner() *MockRunner {
	return &MockRunner{
		Installed: make(map[string]string),
		Handlers:  make(map[string]MockHandler),
	}
}

// RegisterTool marks a binary as installed at the specified path and optional handler.
func (m *MockRunner) RegisterTool(bin, path string, handler MockHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Installed[bin] = path
	if handler != nil {
		m.Handlers[bin] = handler
	}
}

// LookPath returns the registered path for bin, or exec.ErrNotFound.
func (m *MockRunner) LookPath(bin string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if path, ok := m.Installed[bin]; ok {
		return path, nil
	}
	return "", fmt.Errorf("%w: %s", exec.ErrNotFound, bin)
}

// Run executes the registered mock handler for the binary.
func (m *MockRunner) Run(ctx context.Context, bin string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	var stdinBytes []byte
	if stdin != nil {
		var err error
		stdinBytes, err = io.ReadAll(stdin)
		if err != nil {
			return nil, nil, fmt.Errorf("read stdin in mock: %w", err)
		}
	}

	m.mu.Lock()
	m.Calls = append(m.Calls, MockCall{
		Bin:   bin,
		Args:  args,
		Stdin: stdinBytes,
	})
	handler, ok := m.Handlers[bin]
	m.mu.Unlock()

	if !ok {
		return nil, nil, fmt.Errorf("mock handler not registered for binary: %s", bin)
	}

	return handler(ctx, args, stdinBytes)
}

// GetCalls returns a copy of all recorded calls.
func (m *MockRunner) GetCalls() []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]MockCall, len(m.Calls))
	copy(result, m.Calls)
	return result
}
