// internal/agent/scan_executor.go
package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	json "github.com/json-iterator/go"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// ScanExecutor manages the execution of scans by launching sub-agents internally.
type ScanExecutor struct {
	log       *zap.Logger
	globalCtx *core.GlobalContext // Needed to initialize sub-agents
	registry  *ScanRegistry
}

var _ ActionExecutor = (*ScanExecutor)(nil)

// ScanParams defines parameters for the START_SCAN action.
type ScanParams struct {
	Target      string `json:"target"`
	Type        string `json:"type,omitempty"`
	Depth       *int   `json:"depth,omitempty"`
	Concurrency *int   `json:"concurrency,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// ScanJob represents the state of an initiated scan (used for tracking).
type ScanJob struct {
	ID         string     `json:"id"`
	MissionID  string     `json:"mission_id"`
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

// NewScanExecutor requires GlobalContext to initialize sub-agents.
func NewScanExecutor(logger *zap.Logger, globalCtx *core.GlobalContext) *ScanExecutor {
	return &ScanExecutor{
		log:       logger.Named("scan_executor"),
		globalCtx: globalCtx,
		registry: &ScanRegistry{
			jobs: make(map[string]*ScanJob),
		},
	}
}

// Execute handles the START_SCAN action.
func (e *ScanExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	if action.Type != ActionStartScan {
		return e.fail(ErrCodeUnknownAction, fmt.Sprintf("ScanExecutor cannot handle action type: %s", action.Type), nil), nil
	}

	// 1. Parse Parameters
	params := ScanParams{}
	if len(action.Metadata) > 0 {
		data, err := json.Marshal(action.Metadata)
		if err != nil {
			return e.fail(ErrCodeJSONMarshalFailed, fmt.Sprintf("Invalid metadata format: %v", err), nil), nil
		}
		if err := json.Unmarshal(data, &params); err != nil {
			return e.fail(ErrCodeInvalidParameters, fmt.Sprintf("Invalid parameters for START_SCAN: %v", err), nil), nil
		}
	}

	if params.Target == "" {
		return e.fail(ErrCodeInvalidParameters, "Target parameter is required in metadata.", nil), nil
	}

	// 2. Start the scan internally
	job, err := e.StartInternalScan(params)
	if err != nil {
		e.log.Error("Failed to initiate internal scan (sub-agent)", zap.Error(err))
		// The job status is updated within StartInternalScan, we just report the failure to the Mind.
		return e.fail(ErrCodeExecutionFailure, "Failed to initiate scan (sub-agent creation failed).", map[string]interface{}{"details": err.Error()}), nil
	}

	// 3. Format the Result (Accepted)
	// The Mind receives confirmation that the scan started.
	resultData := map[string]interface{}{
		"status":     "accepted",
		"scan_id":    job.ID,
		"mission_id": job.MissionID,
		"message":    fmt.Sprintf("Scan initiated successfully. Status tracked under Scan ID: %s", job.ID),
	}

	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedScanStatus,
		Data:            resultData,
	}, nil
}

// StartInternalScan initializes and launches a sub-agent for the scan mission.
func (e *ScanExecutor) StartInternalScan(params ScanParams) (*ScanJob, error) {
	if e.globalCtx == nil {
		return nil, fmt.Errorf("GlobalContext not available, cannot launch sub-agent")
	}

	// 1. Define the Mission for the sub-agent
	scanID := uuid.New().String()
	missionID := uuid.New().String()

	objective := fmt.Sprintf("Sub-Agent Scan: Analyze %s (Requested by Master Agent)", params.Target)
	if params.Type != "" {
		objective = fmt.Sprintf("Sub-Agent Scan: Perform %s analysis on %s", params.Type, params.Target)
	}

	mission := Mission{
		ID:        missionID,
		ScanID:    scanID,
		Objective: objective,
		TargetURL: params.Target,
		StartTime: time.Now(),
		// TODO: Map Depth/Scope parameters to mission constraints if supported.
	}

	// 2. Initialize Job structure and register
	job := &ScanJob{
		ID:        scanID,
		MissionID: missionID,
		Target:    params.Target,
		Status:    "PENDING",
		StartedAt: time.Now(),
	}
	e.registry.Register(job)

	// 3. Initialize Sub-Agent
	// We pass nil for the session initially.
	// NOTE: This currently means the sub-agent will not have browser capabilities unless browser management is refactored.
	subAgent, err := New(context.Background(), &mission, e.globalCtx, nil)
	if err != nil {
		e.updateJobStatus(job, "FAILED", fmt.Errorf("failed to initialize sub-agent: %w", err))
		return job, err
	}

	// 4. Execute the mission asynchronously
	go e.executeMission(subAgent, job)

	return job, nil
}

// executeMission runs the sub-agent and monitors its lifecycle.
func (e *ScanExecutor) executeMission(subAgent *Agent, job *ScanJob) {
	// Use a long timeout for the scan execution context.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel() // Ensure the context is cancelled when mission finishes (stops the sub-agent)

	e.updateJobStatus(job, "RUNNING", nil)

	// Start the agent loop in a goroutine.
	go func() {
		// Start() will run until ctx is cancelled.
		err := subAgent.Start(ctx)
		if err != nil && ctx.Err() == nil {
			// Agent stopped unexpectedly (e.g., Mind failure) before context cancellation
			e.log.Error("Sub-Agent stopped unexpectedly", zap.Error(err), zap.String("scan_id", job.ID))
			e.updateJobStatus(job, "FAILED", err)
		}
	}()

	// Wait for the mission result or context cancellation.
	select {
	case result := <-subAgent.resultChan:
		// Mission completed successfully (ActionConclude was called by sub-agent)
		e.updateJobStatus(job, "COMPLETED", nil)
		e.log.Info("Sub-Agent mission completed", zap.String("scan_id", job.ID), zap.String("summary", result.Summary))
		// cancel() is called by defer, stopping the sub-agent gracefully.
	case <-ctx.Done():
		// Timeout or parent cancellation occurred before the agent finished the mission.
		if ctx.Err() == context.DeadlineExceeded {
			e.log.Warn("Sub-Agent mission timed out", zap.String("scan_id", job.ID))
			e.updateJobStatus(job, "TIMEOUT", ctx.Err())
		} else {
			e.log.Error("Sub-Agent mission cancelled or failed due to context", zap.Error(ctx.Err()), zap.String("scan_id", job.ID))
			// If the status wasn't already updated to FAILED by the Start() goroutine
			if job.Status == "RUNNING" {
				e.updateJobStatus(job, "FAILED", ctx.Err())
			}
		}
	}
}

func (s *ScanExecutor) updateJobStatus(job *ScanJob, status string, err error) {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()

	// Prevent status regression
	if job.Status == "COMPLETED" || job.Status == "FAILED" || job.Status == "TIMEOUT" {
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

// GetJob retrieves a job by its ID.
func (r *ScanRegistry) GetJob(id string) (*ScanJob, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	job, exists := r.jobs[id]
	return job, exists
}

func (e *ScanExecutor) fail(code ErrorCode, message string, data map[string]interface{}) *ExecutionResult {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["message"] = message
	return &ExecutionResult{
		Status:          "failed",
		ObservationType: ObservedSystemState,
		ErrorCode:       code,
		ErrorDetails:    data,
	}
}
