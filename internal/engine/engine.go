package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/worker"
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
	cfg          *config.Config
	logger       *zap.Logger
	storeService Store
	worker       Worker
	wg           sync.WaitGroup
	globalCtx    *core.GlobalContext
}

// New creates a new TaskEngine.
// The function now accepts interfaces for its dependencies, making it much more testable.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	storeService Store,
	browserManager schemas.BrowserManager,
	kg schemas.KnowledgeGraphClient,
) (*TaskEngine, error) {

	globalCtx := &core.GlobalContext{
		Config:         cfg,
		Logger:         logger,
		BrowserManager: browserManager,
		KGClient:       kg,
	}

	monoWorker, err := worker.NewMonolithicWorker(cfg, logger, globalCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to create monolithic worker: %w", err)
	}

	return &TaskEngine{
		cfg:          cfg,
		logger:       logger.With(zap.String("component", "task_engine")),
		storeService: storeService,
		worker:       monoWorker,
		globalCtx:    globalCtx,
	}, nil
}

// Start launches the worker pool and begins consuming tasks from the provided channel.
// This method now correctly implements the schemas.TaskEngine interface.
func (e *TaskEngine) Start(ctx context.Context, taskChan <-chan schemas.Task) {
	concurrency := e.cfg.Engine.WorkerConcurrency
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
		logger.Error("Invalid target URL in task, discarding", zap.String("url", task.TargetURL), zap.Error(err))
		return
	}

	analysisCtx := &core.AnalysisContext{
		Global:    e.globalCtx,
		Task:      task,
		TargetURL: targetURL,
		Logger:    logger.With(zap.String("task_id", task.TaskID)),
		Findings:  make([]schemas.Finding, 0),
		KGUpdates: &schemas.KnowledgeGraphUpdate{NodesToAdd: []schemas.NodeInput{}, EdgesToAdd: []schemas.EdgeInput{}},
	}

	taskTimeout := e.cfg.Engine.DefaultTaskTimeout
	if taskTimeout <= 0 {
		taskTimeout = 15 * time.Minute // Sensible default if config is invalid.
	}

	// Create a derived context for the specific task execution, respecting the parent context.
	taskCtx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()

	if err := e.worker.ProcessTask(taskCtx, analysisCtx); err != nil {
		// ARCHITECTURAL UPDATE: Improved error classification for better observability.
		// Distinguish between expected cancellation/timeout and actual errors.
		if errors.Is(err, context.DeadlineExceeded) {
			logger.Warn("Task processing timed out", zap.Duration("timeout", taskTimeout), zap.Error(err))
		} else if errors.Is(err, context.Canceled) {
			logger.Warn("Task processing was cancelled", zap.Error(err))
		} else {
			logger.Error("Task processing failed with unexpected error", zap.Error(err))
		}
		return
	}

	if len(analysisCtx.Findings) > 0 || (analysisCtx.KGUpdates != nil && (len(analysisCtx.KGUpdates.NodesToAdd) > 0 || len(analysisCtx.KGUpdates.EdgesToAdd) > 0)) {
		logger.Info("Task generated results, persisting...", zap.Int("findings", len(analysisCtx.Findings)))

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
		logger.Debug("Task completed with no new findings.")
	}
}