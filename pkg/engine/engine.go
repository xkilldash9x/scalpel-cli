// File:         pkg/engine/engine.go
// Description:  This file contains the core task engine, refactored for graceful shutdown,
//               concurrency safety, and correct context propagation.
//
package engine

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
	"github.com/xkilldash9x/scalpel-cli/pkg/store"
	"github.com/xkilldash9x/scalpel-cli/pkg/worker"
)

// TaskEngine manages the in-process distribution of tasks to a pool of workers.
type TaskEngine struct {
	cfg          *config.Config
	logger       *zap.Logger
	storeService *store.Store
	worker       *worker.MonolithicWorker
	taskQueue    chan schemas.Task
	wg           sync.WaitGroup
	globalCtx    *core.GlobalContext
	// isStopping is an atomic flag to prevent submissions after Stop() has been called.
	isStopping atomic.Bool
}

// New creates a new TaskEngine.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	storeService *store.Store,
	browserManager *browser.Manager,
	kg core.KnowledgeGraphClient,
) (*TaskEngine, error) {

	// This global context will be shared by all analyzers.
	globalCtx := &core.GlobalContext{
		Config:         cfg,
		Logger:         logger,
		BrowserManager: browserManager,
		KGClient:       kg,
		// Other global services like HTTPClient, etc. would be added here.
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
		taskQueue:    make(chan schemas.Task, cfg.Engine.QueueSize),
		globalCtx:    globalCtx,
	}, nil
}

// Start launches the worker pool.
func (e *TaskEngine) Start(ctx context.Context) {
	concurrency := e.cfg.Engine.WorkerConcurrency
	if concurrency <= 0 {
		concurrency = 4 // A sensible default.
	}

	e.logger.Info("Starting task engine worker pool", zap.Int("concurrency", concurrency))

	for i := 0; i < concurrency; i++ {
		e.wg.Add(1)
		go e.runWorker(ctx, i+1)
	}
}

// Stop gracefully shuts down the engine, ensuring all queued tasks are processed.
func (e *TaskEngine) Stop() {
	// Atomically set the stopping flag. If it's already set, do nothing.
	if !e.isStopping.CompareAndSwap(false, true) {
		e.logger.Info("Task engine is already in the process of stopping.")
		return
	}

	e.logger.Info("Stopping task engine... closing task queue.")
	// Closing the channel signals workers to finish their current task and exit.
	close(e.taskQueue)

	// Wait for all worker goroutines to finish processing and exit.
	e.wg.Wait()
	e.logger.Info("Task engine stopped gracefully.")
}

// SubmitTask adds a new task to the processing queue.
func (e *TaskEngine) SubmitTask(task schemas.Task) error {
	// CONCURRENCY SAFETY: Check the atomic flag to prevent a panic from sending on a closed channel.
	if e.isStopping.Load() {
		return fmt.Errorf("task engine is shutting down, cannot accept new task")
	}

	select {
	case e.taskQueue <- task:
		e.logger.Debug("Task submitted to queue", zap.String("task_id", task.TaskID), zap.String("type", string(task.Type)))
		return nil
	default:
		// This can happen if the buffered channel is full.
		return fmt.Errorf("task queue is full, cannot accept new task")
	}
}

// runWorker is the main loop for a single worker goroutine.
func (e *TaskEngine) runWorker(ctx context.Context, workerID int) {
	defer e.wg.Done()
	logger := e.logger.With(zap.Int("worker_id", workerID))
	logger.Info("Worker goroutine started")

	// ARCHITECTURAL FIX: Use a `for range` loop on the channel.
	// This is the idiomatic way to process tasks until a channel is closed and drained.
	// It ensures a graceful shutdown, unlike the previous implementation that would exit
	// immediately on context cancellation, potentially leaving tasks in the queue.
	for task := range e.taskQueue {
		// The parent context `ctx` is passed to `process` so that individual,
		// long-running tasks can still be cancelled (e.g., by a global timeout or Ctrl+C).
		e.process(ctx, task, logger)
	}

	logger.Info("Task queue closed and drained, worker shutting down.")
}

// process handles the execution of a single task.
func (e *TaskEngine) process(ctx context.Context, task schemas.Task, logger *zap.Logger) {
	logger.Info("Processing task", zap.String("task_id", task.TaskID), zap.String("task_type", string(task.Type)))

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
		KGUpdates: &schemas.KGUpdates{Nodes: []schemas.KGNode{}, Edges: []schemas.KGEdge{}},
	}

	taskTimeout := e.cfg.Engine.DefaultTaskTimeout
	if taskTimeout <= 0 {
		taskTimeout = 15 * time.Minute // Sensible default if config is invalid.
	}
	taskCtx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()

	if err := e.worker.ProcessTask(taskCtx, analysisCtx); err != nil {
		logger.Error("Task processing failed", zap.Error(err))
		return
	}

	if len(analysisCtx.Findings) > 0 || (analysisCtx.KGUpdates != nil && (len(analysisCtx.KGUpdates.Nodes) > 0 || len(analysisCtx.KGUpdates.Edges) > 0)) {
		logger.Info("Task generated results, persisting...", zap.Int("findings", len(analysisCtx.Findings)))

		resultEnvelope := &schemas.ResultEnvelope{
			ScanID:    task.ScanID,
			TaskID:    task.TaskID,
			Timestamp: time.Now().UTC(),
			Findings:  analysisCtx.Findings,
			KGUpdates: analysisCtx.KGUpdates,
		}

		// CONTEXT PROPAGATION: Derive persistence context from the main `ctx` to respect shutdown signals.
		persistCtx, persistCancel := context.WithTimeout(ctx, 30*time.Second)
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