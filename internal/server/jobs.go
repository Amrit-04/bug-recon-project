package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// JobStatus represents the lifecycle state of a long-running background task.
type JobStatus string

const (
	JobStatusQueued    JobStatus = "Queued"
	JobStatusRunning   JobStatus = "Running"
	JobStatusCompleted JobStatus = "Completed"
	JobStatusFailed    JobStatus = "Failed"
	JobStatusCancelled JobStatus = "Cancelled"
)

// Supported job types
const (
	JobTypeRecon         = "recon"
	JobTypeIDORInventory = "idor_inventory"
	JobTypeIDORCompare   = "idor_compare"
	JobTypeRCEDiscover   = "rce_discover"
	JobTypeRCEValidate   = "rce_validate"
	JobTypeToolRun       = "tool_run"
)

// Job represents a background task tracked across the system lifecycle.
type Job struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	WorkspaceID  string         `json:"workspace_id"`
	ScopeTarget  string         `json:"scope_target,omitempty"`
	Status       JobStatus      `json:"status"`
	Stage        string         `json:"stage,omitempty"`
	StageIndex   int            `json:"stage_index"`
	TotalStages  int            `json:"total_stages"`
	Progress     int            `json:"progress"` // 0-100
	Detail       string         `json:"detail,omitempty"`
	ErrorDetails string         `json:"error_details,omitempty"`
	Logs         []string       `json:"logs,omitempty"`
	Artifacts    []string       `json:"artifacts,omitempty"`
	Config       map[string]any `json:"config,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	StartedAt    *time.Time     `json:"started_at,omitempty"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`

	// In-memory runtime cancellation (never marshaled to JSON)
	cancel context.CancelFunc `json:"-"`
	ctx    context.Context    `json:"-"`
}

// JobRunnerFunc is the function executed when a background job runs.
type JobRunnerFunc func(ctx context.Context, job *Job, update func(stageIndex int, stage, detail string, progress int), emitLog func(msg string)) error

// JobManager manages background jobs, bounded concurrency, persistence, and event emissions.
type JobManager struct {
	mu          sync.RWMutex
	jobs        map[string]*Job
	queue       chan *queuedJob
	broker      *EventBroker
	storageFile string
	sem         chan struct{} // Bounded concurrency semaphore
	closed      bool
}

type queuedJob struct {
	job    *Job
	runner JobRunnerFunc
}

// NewJobManager creates and starts a JobManager.
func NewJobManager(storagePath string, maxConcurrent int, broker *EventBroker) (*JobManager, error) {
	if maxConcurrent <= 0 {
		maxConcurrent = 3
	}

	jm := &JobManager{
		jobs:        make(map[string]*Job),
		queue:       make(chan *queuedJob, 100),
		broker:      broker,
		storageFile: storagePath,
		sem:         make(chan struct{}, maxConcurrent),
	}

	// Load existing jobs from disk
	if err := jm.load(); err != nil && !os.IsNotExist(err) {
		// Log or warn, but do not crash
		_ = err
	}

	// Mark any interrupted jobs as Failed
	now := time.Now()
	for _, j := range jm.jobs {
		if j.Status == JobStatusRunning || j.Status == JobStatusQueued {
			j.Status = JobStatusFailed
			j.ErrorDetails = "Job interrupted by backend restart"
			j.CompletedAt = &now
		}
	}
	_ = jm.save()

	// Launch background worker pool
	for i := 0; i < maxConcurrent; i++ {
		go jm.worker()
	}

	return jm, nil
}

func (jm *JobManager) worker() {
	for qj := range jm.queue {
		if qj == nil {
			return
		}

		jm.sem <- struct{}{}
		jm.runJob(qj)
		<-jm.sem
	}
}

func (jm *JobManager) runJob(qj *queuedJob) {
	job := qj.job

	jm.mu.Lock()
	if job.Status == JobStatusCancelled {
		jm.mu.Unlock()
		return
	}
	now := time.Now()
	job.Status = JobStatusRunning
	job.StartedAt = &now
	ctx, cancel := context.WithCancel(context.Background())
	job.ctx = ctx
	job.cancel = cancel
	jm.mu.Unlock()

	_ = jm.save()

	if jm.broker != nil {
		jm.broker.Broadcast(job.ID, EventJobStart, map[string]any{
			"job_id":       job.ID,
			"type":         job.Type,
			"workspace_id": job.WorkspaceID,
			"status":       string(job.Status),
			"detail":       job.Detail,
		})
	}

	updateFunc := func(stageIndex int, stage, detail string, progress int) {
		jm.mu.Lock()
		job.StageIndex = stageIndex
		job.Stage = stage
		job.Detail = detail
		if progress >= 0 && progress <= 100 {
			job.Progress = progress
		}
		jm.mu.Unlock()

		if jm.broker != nil {
			jm.broker.Broadcast(job.ID, EventProgress, map[string]any{
				"job_id":      job.ID,
				"stage_index": stageIndex,
				"stage":       stage,
				"detail":      detail,
				"progress":    job.Progress,
			})
		}
	}

	logFunc := func(msg string) {
		timestamped := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg)
		jm.mu.Lock()
		job.Logs = append(job.Logs, timestamped)
		if len(job.Logs) > 1000 {
			job.Logs = job.Logs[len(job.Logs)-1000:]
		}
		jm.mu.Unlock()

		if jm.broker != nil {
			jm.broker.Broadcast(job.ID, EventLog, map[string]any{
				"job_id": job.ID,
				"log":    timestamped,
			})
		}
	}

	// Execute job logic
	err := qj.runner(ctx, job, updateFunc, logFunc)

	jm.mu.Lock()
	completedNow := time.Now()
	job.CompletedAt = &completedNow

	if err != nil {
		if ctx.Err() == context.Canceled || job.Status == JobStatusCancelled {
			job.Status = JobStatusCancelled
			job.Detail = "Job cancelled by user"
		} else {
			job.Status = JobStatusFailed
			job.ErrorDetails = err.Error()
			job.Detail = fmt.Sprintf("Failed: %v", err)
		}
	} else {
		if job.Status != JobStatusCancelled {
			job.Status = JobStatusCompleted
			job.Progress = 100
		}
	}
	jm.mu.Unlock()

	_ = jm.save()

	if jm.broker != nil {
		evType := EventJobCompleted
		if job.Status == JobStatusFailed {
			evType = EventError
		} else if job.Status == JobStatusCancelled {
			evType = EventJobCancelled
		}
		jm.broker.Broadcast(job.ID, evType, map[string]any{
			"job_id":        job.ID,
			"status":        string(job.Status),
			"detail":        job.Detail,
			"error_details": job.ErrorDetails,
			"progress":      job.Progress,
			"artifacts":     job.Artifacts,
		})
	}
}

// Submit enqueues a new background job.
func (jm *JobManager) Submit(jobType, workspaceID, scopeTarget string, config map[string]any, runner JobRunnerFunc) (*Job, error) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if jm.closed {
		return nil, fmt.Errorf("job manager is closed")
	}

	// Generate random safe ID: job-<type>-<timestamp>-<rand>
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	jobID := fmt.Sprintf("job-%s-%d-%s", jobType, time.Now().Unix(), hex.EncodeToString(b))

	job := &Job{
		ID:          jobID,
		Type:        jobType,
		WorkspaceID: workspaceID,
		ScopeTarget: scopeTarget,
		Status:      JobStatusQueued,
		Stage:       "queued",
		StageIndex:  0,
		TotalStages: 1,
		Progress:    0,
		Detail:      "Job queued for processing",
		Logs:        []string{fmt.Sprintf("[%s] Job %s submitted", time.Now().Format("15:04:05"), jobID)},
		Config:      config,
		CreatedAt:   time.Now(),
	}

	jm.jobs[jobID] = job
	_ = jm.saveUnlocked()

	select {
	case jm.queue <- &queuedJob{job: job, runner: runner}:
	default:
		job.Status = JobStatusFailed
		job.ErrorDetails = "Job queue is full"
		_ = jm.saveUnlocked()
		return nil, fmt.Errorf("job queue is full")
	}

	return job, nil
}

// GetJob returns a job by ID.
func (jm *JobManager) GetJob(jobID string) (*Job, error) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	job, exists := jm.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}
	// Return shallow copy
	cp := *job
	return &cp, nil
}

// ListJobs returns all tracked jobs sorted newest first.
func (jm *JobManager) ListJobs(workspaceID, statusFilter string) []*Job {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	var list []*Job
	for _, j := range jm.jobs {
		if workspaceID != "" && j.WorkspaceID != workspaceID {
			continue
		}
		if statusFilter != "" && string(j.Status) != statusFilter {
			continue
		}
		cp := *j
		list = append(list, &cp)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})

	return list
}

// CancelJob cancels an active or queued job.
func (jm *JobManager) CancelJob(jobID string) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	job, exists := jm.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}

	if job.Status == JobStatusCompleted || job.Status == JobStatusFailed || job.Status == JobStatusCancelled {
		return nil // Already terminal
	}

	job.Status = JobStatusCancelled
	job.Detail = "Job cancelled by user"
	now := time.Now()
	job.CompletedAt = &now
	job.Logs = append(job.Logs, fmt.Sprintf("[%s] Job cancelled by user", time.Now().Format("15:04:05")))

	if job.cancel != nil {
		job.cancel()
	}

	_ = jm.saveUnlocked()

	if jm.broker != nil {
		jm.broker.Broadcast(job.ID, EventJobCancelled, map[string]any{
			"job_id": job.ID,
			"status": string(job.Status),
			"detail": job.Detail,
		})
	}

	return nil
}

// Close gracefully stops the job manager.
func (jm *JobManager) Close() {
	jm.mu.Lock()
	jm.closed = true
	close(jm.queue)
	jm.mu.Unlock()
}

func (jm *JobManager) save() error {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	return jm.saveUnlocked()
}

func (jm *JobManager) saveUnlocked() error {
	if jm.storageFile == "" {
		return nil
	}

	dir := filepath.Dir(jm.storageFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	var list []*Job
	for _, j := range jm.jobs {
		list = append(list, j)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})

	// Retain only latest 200 jobs in file
	if len(list) > 200 {
		list = list[:200]
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write via temp file in same directory + sync
	tmpFile, err := os.CreateTemp(dir, "jobs-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, jm.storageFile)
}

func (jm *JobManager) load() error {
	if jm.storageFile == "" {
		return nil
	}

	data, err := os.ReadFile(jm.storageFile)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}

	var list []*Job
	if err := json.Unmarshal(data, &list); err != nil {
		// Log or return nil to avoid crashing on corrupted file
		return nil
	}

	for _, j := range list {
		if j != nil && j.ID != "" {
			jm.jobs[j.ID] = j
		}
	}

	return nil
}
