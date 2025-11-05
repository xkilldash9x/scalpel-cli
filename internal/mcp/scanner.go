// File: internal/mcp/scanner.go
package mcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ScanService manages the execution of the scalpel-cli binary.
type ScanService struct {
	log      *zap.Logger
	registry *ScanRegistry
}

// ScanJob represents the state of an initiated scan.
type ScanJob struct {
	ID         string     `json:"id"`
	Target     string     `json:"target"`
	Status     string     `json:"status"` // PENDING, RUNNING, COMPLETED, FAILED, TIMEOUT
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// ScanRegistry tracks active and recent scans thread-safely in memory.
type ScanRegistry struct {
	jobs map[string]*ScanJob
	mu   sync.RWMutex
}

func NewScanService(logger *zap.Logger) *ScanService {
	return &ScanService{
		log: logger.Named("mcp_scan_service"),
		registry: &ScanRegistry{
			jobs: make(map[string]*ScanJob),
		},
	}
}

// StartScan executes the scalpel-cli scan command asynchronously.
func (s *ScanService) StartScan(params ScanParams) (*ScanJob, error) {
	// 1. Locate the binary
	binaryName := "scalpel-cli"
	path, err := exec.LookPath(binaryName)
	if err != nil {
		// Fallback for development environments if it's in the current directory
		if p, err := exec.LookPath("./" + binaryName); err == nil {
			path = p
		} else {
			return nil, fmt.Errorf("scalpel-cli binary not found in PATH or current directory: %w", err)
		}
	}

	// 2. Construct arguments
	args := []string{"scan"}

	// Add optional flags
	if params.Depth != nil {
		args = append(args, "--depth", fmt.Sprintf("%d", *params.Depth))
	}
	if params.Concurrency != nil {
		args = append(args, "--concurrency", fmt.Sprintf("%d", *params.Concurrency))
	}
	if params.Scope != "" {
		args = append(args, "--scope", params.Scope)
	}

	// Target is the final argument
	args = append(args, params.Target)

	s.log.Info("Initiating scan via CLI execution", zap.String("target", params.Target), zap.Strings("args", args))

	// 3. Initialize Job structure
	// Use a temporary ID until the real Scan ID is captured from the CLI output.
	job := &ScanJob{
		ID:        "pending-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		Target:    params.Target,
		Status:    "PENDING",
		StartedAt: time.Now(),
	}
	s.registry.Register(job)

	// 4. Execute the command asynchronously
	go s.executeCommand(path, args, job)

	// Return immediately so the API remains responsive
	return job, nil
}

// executeCommand runs the command and monitors its output.
func (s *ScanService) executeCommand(path string, args []string, job *ScanJob) {
	// Use a long timeout for the scan execution context.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)

	// Capture stdout/stderr to parse the Scan ID and monitor progress
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.updateJobStatus(job, "FAILED", fmt.Errorf("failed to capture stdout: %w", err))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		s.updateJobStatus(job, "FAILED", fmt.Errorf("failed to capture stderr: %w", err))
		return
	}

	if err := cmd.Start(); err != nil {
		s.updateJobStatus(job, "FAILED", fmt.Errorf("failed to start command: %w", err))
		return
	}
	s.updateJobStatus(job, "RUNNING", nil)

	// Monitor output in parallel
	var wg sync.WaitGroup
	wg.Add(2)
	go s.monitorOutput(stdout, job, &wg)
	go s.monitorError(stderr, &wg)
	wg.Wait()

	// Wait for the command process to finish
	err = cmd.Wait()
	if err != nil {
		// Check if the failure was due to timeout
		if ctx.Err() == context.DeadlineExceeded {
			s.updateJobStatus(job, "TIMEOUT", err)
		} else {
			s.updateJobStatus(job, "FAILED", err)
		}
	} else if job.Status == "RUNNING" {
		// Only update to COMPLETED if it hasn't failed or timed out.
		s.updateJobStatus(job, "COMPLETED", nil)
	}
}

// Regex to find the Scan ID in the CLI output, matching the format in cmd/scan.go
// Example: "Scan Complete. Scan ID: 12345-abcde"
var scanIDRegex = regexp.MustCompile(`Scan Complete\. Scan ID: ([a-f0-9\-]+)`)

func (s *ScanService) monitorOutput(pipe io.Reader, job *ScanJob, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text()
		// Optionally log the CLI output (can be verbose)
		// s.log.Debug("CLI Stdout", zap.String("line", line))

		// Parse for Scan ID
		if matches := scanIDRegex.FindStringSubmatch(line); matches != nil && len(matches) > 1 {
			scanID := matches[1]
			s.log.Info("Captured real Scan ID from CLI output", zap.String("scan_id", scanID))
			// Update the registry with the real ID.
			s.registry.UpdateID(job, scanID)
		}
	}
}

func (s *ScanService) monitorError(pipe io.Reader, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		// Log errors from the CLI execution stderr
		s.log.Error("CLI Stderr", zap.String("line", scanner.Text()))
	}
}

func (s *ScanService) updateJobStatus(job *ScanJob, status string, err error) {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()

	// Prevent status regression (e.g., don't set RUNNING if already finished).
	if job.Status == "COMPLETED" || job.Status == "FAILED" || job.Status == "TIMEOUT" {
		// Allow updating the error message even if finished, but not the status.
		if err != nil && job.Error == "" {
			job.Error = err.Error()
		}
		return
	}

	job.Status = status

	// Set finished time if the job is terminating.
	if status != "RUNNING" && status != "PENDING" {
		now := time.Now()
		job.FinishedAt = &now
	}

	if err != nil {
		job.Error = err.Error()
	}
	s.log.Info("Scan job status updated", zap.String("id", job.ID), zap.String("status", status), zap.Error(err))
}

// Register adds a new job to the registry.
func (r *ScanRegistry) Register(job *ScanJob) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs[job.ID] = job
}

// UpdateID updates the job ID once the actual Scan ID is known from the CLI output.
func (r *ScanRegistry) UpdateID(job *ScanJob, newID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Check if the ID hasn't already been updated
	if job.ID == newID {
		return
	}
	// Remove the old pending ID entry
	delete(r.jobs, job.ID)
	// Update the job object and re-register with the new ID
	job.ID = newID
	r.jobs[newID] = job
}

// GetJob retrieves a job by its ID.
func (r *ScanRegistry) GetJob(id string) (*ScanJob, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	job, exists := r.jobs[id]
	return job, exists
}
