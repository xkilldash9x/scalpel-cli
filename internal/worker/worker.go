// -- pkg/worker/worker.go --
package worker

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// MonolithicWorker processes tasks directly without a message queue.
// It acts as a dispatcher to various analysis modules (adapters).
type MonolithicWorker struct {
	cfg             *config.Config
	logger          *zap.Logger
	globalCtx       *core.GlobalContext
	storeService    *store.Store
	adapterRegistry map[string]core.Analyzer
}

// NewMonolithicWorker creates a new worker instance for the monolithic architecture.
func NewMonolithicWorker(
	cfg *config.Config,
	logger *zap.Logger,
	globalCtx *core.GlobalContext,
	storeService *store.Store,
) (*MonolithicWorker, error) {

	w := &MonolithicWorker{
		cfg:             cfg,
		logger:          logger.With(zap.String("component", "monolithic_worker")),
		globalCtx:       globalCtx,
		storeService:    storeService,
		adapterRegistry: make(map[string]core.Analyzer),
	}

	// The adapter registry is the key to modularity. It maps a task type
	// to the specific analyzer that can handle it.
	if err := w.registerAdapters(); err != nil {
		return nil, fmt.Errorf("failed to register worker adapters: %w", err)
	}

	return w, nil
}

// registerAdapters populates the worker's registry of available analyzers.
func (w *MonolithicWorker) registerAdapters() error {
	// Each adapter is initialized and mapped to the TaskType it handles.
	w.adapterRegistry[schemas.TaskAnalyzeWebPageTaint] = adapters.NewTaintAdapter()
	w.adapterRegistry[schemas.TaskTestAuthATO] = adapters.NewATOAdapter()
	w.adapterRegistry[schemas.TaskTestAuthIDOR] = adapters.NewIDORAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeHeaders] = adapters.NewHeadersAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeJWT] = adapters.NewJWTAdapter()
    w.adapterRegistry[schemas.TaskAgentMission] = adapters.NewAgentAdapter() // The agent is just another module!

	w.logger.Info("Analyzer adapters registered", zap.Int("count", len(w.adapterRegistry)))
	return nil
}

// ProcessTask is the main entry point for executing an analysis task.
// It finds the correct adapter and runs the analysis.
func (w *MonolithicWorker) ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	task := analysisCtx.Task

	// 1. Find the right tool for the job from our registry.
	adapter, exists := w.adapterRegistry[task.Type]
	if !exists {
		return fmt.Errorf("monolithic worker has no adapter for task type '%s'", task.Type)
	}

	analysisCtx.Logger.Info("Dispatching task to adapter", zap.String("adapter_name", adapter.Name()))

	// 2. Run the analysis.
	// The adapter will populate the Findings and KGUpdates in the analysisCtx.
	if err := adapter.Analyze(ctx, analysisCtx); err != nil {
		return fmt.Errorf("adapter '%s' failed during analysis: %w", adapter.Name(), err)
	}

	analysisCtx.Logger.Info("Adapter finished analysis", zap.String("adapter_name", adapter.Name()))

	// 3. Results are returned via the modified analysisCtx.
	// The TaskEngine is responsible for persisting them.
	return nil
}
