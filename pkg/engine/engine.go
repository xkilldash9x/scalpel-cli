// -- pkg/engine/engine.go --
package engine

import (
	"context"
	"fmt"
	"net/url"
	"sync"
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
}

// New creates a new TaskEngine.
func New(
	cfg *config.Config,
	logger *zap.Logger,
	storeService *store.Store,
	browserManager *browser.Manager,
) (*TaskEngine, error) {

	// This global context will be shared by all analyzers.
	globalCtx := &core.GlobalContext{
		Config:           cfg,
		Logger:           logger,
		BrowserManager:   browserManager,
		Store:            storeService,
		// Other global services like HTTPClient, KG, etc. would be added here.
	}

	// The monolithic worker holds the analysis logic.
	monoWorker, err := worker.NewMonolithicWorker(cfg, logger, globalCtx, storeService)
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
		concurrency = 4 // a sensible default.
	}

	e.logger.Info("Starting task engine worker pool", zap.Int("concurrency", concurrency))

	for i := 0; i < concurrency; i++ {
		e.wg.Add(1)
		go e.runWorker(ctx, i+1)
	}
}

// Stop gracefully shuts down the engine and its workers.
func (e *TaskEngine) Stop() {
	e.logger.Info("Stopping task engine... waiting for tasks to complete.")
	close(e.taskQueue)
	e.wg.Wait()
	e.logger.Info("Task engine stopped.")
}

// SubmitTask adds a new task to the processing queue.
func (e *TaskEngine) SubmitTask(task schemas.Task) error {
	select {
	case e.taskQueue <- task:
		e.logger.Debug("Task submitted to queue", zap.String("task_id", task.TaskID), zap.String("type", task.Type))
		return nil
	default:
		return fmt.Errorf("task queue is full, cannot accept new task")
	}
}

// runWorker is the main loop for a single worker goroutine.
func (e *TaskEngine) runWorker(ctx context.Context, workerID int) {
	defer e.wg.Done()
	logger := e.logger.With(zap.Int("worker_id", workerID))
	logger.Info("Worker goroutine started")

	for {
		select {
		case task, ok := <-e.taskQueue:
			if !ok {
				logger.Info("Task queue closed, worker shutting down.")
				return
			}
			e.process(ctx, task, logger)
		case <-ctx.Done():
			logger.Info("Context cancelled, worker shutting down.")
			return
		}
	}
}

// process handles the execution of a single task.
func (e *TaskEngine) process(ctx context.Context, task schemas.Task, logger *zap.Logger) {
	logger.Info("Processing task", zap.String("task_id", task.TaskID), zap.String("task_type", task.Type))

	// Prepare the analysis context for this specific task.
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

	// Set a timeout for the task.
	taskTimeout := e.cfg.Engine.DefaultTaskTimeout
	taskCtx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()

	// Execute the analysis via the monolithic worker.
	err = e.worker.ProcessTask(taskCtx, analysisCtx)
	if err != nil {
		logger.Error("Task processing failed", zap.Error(err))
		// Here you could add logic for retries or error reporting.
		return
	}

	// If the analysis produced findings or graph updates, persist them.
	if len(analysisCtx.Findings) > 0 || (analysisCtx.KGUpdates != nil && (len(analysisCtx.KGUpdates.Nodes) > 0 || len(analysisCtx.KGUpdates.Edges) > 0)) {
		logger.Info("Task generated results, persisting...", zap.Int("findings", len(analysisCtx.Findings)))

		resultEnvelope := &schemas.ResultEnvelope{
			TaskID:    task.TaskID,
			Timestamp: time.Now().UTC(),
			Findings:  analysisCtx.Findings,
			KGUpdates: analysisCtx.KGUpdates,
		}

		// Persist results directly to the store.
		persistCtx, persistCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer persistCancel()

		if err := e.storeService.PersistData(persistCtx, resultEnvelope); err != nil {
			logger.Error("Failed to persist task results", zap.Error(err))
		} else {
			logger.Info("Successfully persisted task results.")
		}
	} else {
		logger.Info("Task completed with no new findings.")
	}
}
