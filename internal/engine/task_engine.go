// internal/engine/task_engine.go
package engine

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Interfaces for Dependency Inversion --

// Worker defines the interface for any component that can process a task.
// This allows us to easily swap in different worker implementations or mocks.
type Worker interface {
	ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error
}

// Store defines the interface for any component that can persist task results.
// This decouples the engine from a specific storage implementation.
type Store interface {
	PersistData(ctx context.Context, data *schemas.ResultEnvelope) error
}

// TaskEngine manages the in-process distribution of tasks to a pool of workers.
type TaskEngine struct {
	cfg          config.Interface
	logger       *zap.Logger
	storeService Store
	worker       Worker
	wg           sync.WaitGroup
	globalCtx    *core.GlobalContext

	// stateLock protects the running state of the engine (Fix 2).
	stateLock sync.Mutex
	isRunning bool
}

// New creates a new TaskEngine.
// By accepting its dependencies (like the Worker) as interfaces, this function
// adheres to the Dependency Inversion Principle. The responsibility of creating
// concrete instances is moved to the application's composition root, making the
// engine more modular, decoupled, and easier to test.
func New(
	cfg config.Interface,
	logger *zap.Logger,
	storeService Store,
	worker Worker,
	globalCtx *core.GlobalContext,
) (*TaskEngine, error) {

	// Fix 1: Validate all dependencies to prevent runtime panics.
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}
	if storeService == nil {
		return nil, errors.New("store service cannot be nil")
	}
	if worker == nil {
		return nil, errors.New("worker cannot be nil")
	}
	if globalCtx == nil {
		return nil, errors.New("global context cannot be nil")
	}

	return &TaskEngine{
		cfg:          cfg,
		logger:       logger.With(zap.String("component", "task_engine")),
		storeService: storeService,
		worker:       worker,
		globalCtx:    globalCtx,
		isRunning:    false,
	}, nil
}

// Start launches the worker pool and begins consuming tasks from the provided channel.
// This method now correctly implements the schemas.TaskEngine interface.
func (e *TaskEngine) Start(ctx context.Context, taskChan <-chan schemas.Task) {
	// Fix 2: Prevent re-entrant calls to Start.
	e.stateLock.Lock()
	if e.isRunning {
		e.stateLock.Unlock()
		e.logger.Warn("TaskEngine.Start called, but engine is already running.")
		return
	}
	e.isRunning = true
	e.stateLock.Unlock()

	concurrency := e.cfg.Engine().WorkerConcurrency
	if concurrency <= 0 {
		concurrency = 4 // A sensible default.
	}

	e.logger.Info("Starting task engine worker pool", zap.Int("concurrency", concurrency))

	for i := 0; i < concurrency; i++ {
		e.wg.Add(1)
		// The worker now consumes from the taskChan passed in from the orchestrator.
		go e.runWorker(ctx, i+1, taskChan)
	}
}

// Stop gracefully shuts down the engine by waiting for all workers to finish.
func (e *TaskEngine) Stop() {
	e.logger.Info("Stopping task engine... waiting for workers to finish.")
	// We wait for workers to exit, which they will do if the context is cancelled or the channel is closed.
	e.wg.Wait()

	// Fix 2: Reset running state after successful stop.
	e.stateLock.Lock()
	e.isRunning = false
	e.stateLock.Unlock()

	e.logger.Info("Task engine stopped gracefully.")
}

// runWorker is the main loop for a single worker goroutine.
// It utilizes a select statement to handle both incoming tasks and context cancellation.
func (e *TaskEngine) runWorker(ctx context.Context, workerID int, taskChan <-chan schemas.Task) {
	defer e.wg.Done()
	logger := e.logger.With(zap.Int("worker_id", workerID))
	logger.Info("Worker goroutine started")

	// ARCHITECTURAL UPDATE: Replaced for-range with for-select to respect context cancellation.
	for {
		select {
		case <-ctx.Done():
			// Context was cancelled (e.g., global shutdown signal).
			// We stop waiting for new tasks immediately.
			logger.Info("Context cancelled, worker shutting down immediately.", zap.Error(ctx.Err()))
			return
		case task, ok := <-taskChan:
			if !ok {
				// Channel closed and drained by the producer.
				logger.Info("Task queue closed and drained, worker shutting down gracefully.")
				return
			}
			// Received a new task, process it.
			e.process(ctx, task, logger)
		}
	}
}

// process handles the execution of a single task.
func (e *TaskEngine) process(ctx context.Context, task schemas.Task, logger *zap.Logger) {
	logger.Info("Processing task", zap.String("task_id", task.TaskID), zap.String("task_type", string(task.Type)))

	// ARCHITECTURAL UPDATE: Added pre-check for context cancellation.
	// Check context before starting heavy work.
	if ctx.Err() != nil {
		logger.Warn("Context cancelled before task processing started", zap.Error(ctx.Err()))
		return
	}

	targetURL, err := url.Parse(task.TargetURL)
	if err != nil {
		// Updated log message for clarity.
		logger.Error("Invalid target URL format in task, discarding", zap.String("url", task.TargetURL), zap.Error(err))
		return
	}

	// Fix 4: Ensure the URL is absolute (has scheme and host).
	if !targetURL.IsAbs() || targetURL.Host == "" {
		logger.Error("Target URL is not absolute or missing host, discarding", zap.String("url", task.TargetURL))
		return
	}

	analysisCtx := &core.AnalysisContext{
		Global:    e.globalCtx,
		Task:      task,
		TargetURL: targetURL,
		Logger:    logger.With(zap.String("task_id", task.TaskID)),
		Findings:  make([]schemas.Finding, 0),
		// Fix 5: Initialize KGUpdates to nil to reduce memory allocations.
		// Workers are responsible for initializing it if they have data.
		KGUpdates: nil,
	}

	taskTimeout := e.cfg.Engine().DefaultTaskTimeout
	if taskTimeout <= 0 {
		taskTimeout = 15 * time.Minute // Sensible default if config is invalid.
	}

	// Create a derived context for the specific task execution, respecting the parent context.
	taskCtx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()

	// Execute the task.
	processingErr := e.worker.ProcessTask(taskCtx, analysisCtx)

	// Fix 3: Handle partial results on timeout/cancellation.
	if processingErr != nil {
		// ARCHITECTURAL UPDATE: Improved error classification for better observability.
		// Distinguish between expected cancellation/timeout and actual errors.
		if errors.Is(processingErr, context.DeadlineExceeded) {
			logger.Warn("Task processing timed out. Proceeding to save partial results.", zap.Duration("timeout", taskTimeout), zap.Error(processingErr))
			// Do not return; fall through to persistence logic.
		} else if errors.Is(processingErr, context.Canceled) {
			logger.Warn("Task processing was cancelled. Proceeding to save partial results.", zap.Error(processingErr))
			// Do not return; fall through to persistence logic.
		} else {
			// This is a critical/unexpected error. We discard results as the state might be corrupted or unreliable.
			logger.Error("Task processing failed with unexpected error. Discarding results.", zap.Error(processingErr))
			return
		}
	}

	// Check if there are results (findings or KG updates) to persist, regardless of whether the task completed fully or was interrupted.
	if len(analysisCtx.Findings) > 0 || (analysisCtx.KGUpdates != nil && (len(analysisCtx.KGUpdates.NodesToAdd) > 0 || len(analysisCtx.KGUpdates.EdgesToAdd) > 0)) {
		logger.Info("Task generated results (potentially partial), persisting...", zap.Int("findings", len(analysisCtx.Findings)))

		resultEnvelope := &schemas.ResultEnvelope{
			ScanID:    task.ScanID,
			TaskID:    task.TaskID,
			Timestamp: time.Now().UTC(),
			Findings:  analysisCtx.Findings,
			KGUpdates: analysisCtx.KGUpdates,
		}

		//  Use a background context for persistence with a specific timeout.
		// This ensures we attempt to save results even if the parent scan context (ctx) is cancelled during shutdown.
		persistCtx, persistCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer persistCancel()

		if err := e.storeService.PersistData(persistCtx, resultEnvelope); err != nil {
			logger.Error("Failed to persist task results", zap.Error(err))
		} else {
			logger.Info("Successfully persisted task results.")
		}
	} else {
		// Log appropriately if the task was interrupted but yielded no results.
		if processingErr != nil {
			logger.Debug("Task interrupted with no results found prior to interruption.")
		} else {
			logger.Debug("Task completed with no new findings.")
		}
	}
}
