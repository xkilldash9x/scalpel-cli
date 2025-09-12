package worker

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// MonolithicWorker processes tasks in-process.
// It serves as a central dispatcher, routing analysis tasks to the appropriate,
// specialized adapters based on the task type.
type MonolithicWorker struct {
	cfg             *config.Config
	logger          *zap.Logger
	globalCtx       *core.GlobalContext
	adapterRegistry map[schemas.TaskType]core.Analyzer
}

// NewMonolithicWorker initializes and returns a new worker instance.
// It sets up the internal registry of all available analysis adapters.
func NewMonolithicWorker(
	cfg *config.Config,
	logger *zap.Logger,
	globalCtx *core.GlobalContext,
) (*MonolithicWorker, error) {

	w := &MonolithicWorker{
		cfg:             cfg,
		logger:          logger.With(zap.String("component", "worker")),
		globalCtx:       globalCtx,
		adapterRegistry: make(map[schemas.TaskType]core.Analyzer),
	}

	// Populates the adapter registry, mapping task types to their handlers.
	if err := w.registerAdapters(); err != nil {
		return nil, fmt.Errorf("failed to register worker adapters: %w", err)
	}

	return w, nil
}

// registerAdapters builds the map of task types to their corresponding analyzers.
// This modular design allows new analysis capabilities to be added easily
// by simply creating a new adapter and registering it here.
func (w *MonolithicWorker) registerAdapters() error {
	// Initialize and register each analysis adapter.
	// More complex adapters can receive dependencies here during instantiation.
	w.adapterRegistry[schemas.TaskAnalyzeWebPageTaint] = adapters.NewTaintAdapter()
	w.adapterRegistry[schemas.TaskTestAuthATO] = adapters.NewATOAdapter()
	w.adapterRegistry[schemas.TaskTestAuthIDOR] = adapters.NewIDORAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeHeaders] = adapters.NewHeadersAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeJWT] = adapters.NewJWTAdapter()

	// The agent adapter is a stateless component.
	w.adapterRegistry[schemas.TaskAgentMission] = adapters.NewAgentAdapter()

	w.logger.Info("Analyzer adapters registered", zap.Int("count", len(w.adapterRegistry)))
	return nil
}

// ProcessTask executes a single analysis task.
// It looks up the correct adapter and delegates the analysis execution. Results
// are communicated back by modifying the provided AnalysisContext.
func (w *MonolithicWorker) ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	task := analysisCtx.Task

	// Find the appropriate adapter from the registry for the given task type.
	adapter, exists := w.adapterRegistry[task.Type]
	if !exists {
		// This indicates a logic error or a misconfigured task.
		return fmt.Errorf("no adapter registered for task type '%s'", task.Type)
	}

	analysisCtx.Logger.Info("Dispatching task to adapter", zap.String("adapter_name", adapter.Name()))

	// Delegate the core analysis logic to the selected adapter.
	if err := adapter.Analyze(ctx, analysisCtx); err != nil {
		// Wrap the error to provide context about which adapter failed.
		return fmt.Errorf("adapter '%s' failed during analysis: %w", adapter.Name(), err)
	}

	analysisCtx.Logger.Info("Adapter finished analysis", zap.String("adapter_name", adapter.Name()))

	// A nil return indicates successful execution. The orchestrator is responsible
	// for handling the results now present in the analysisCtx.
	return nil
}