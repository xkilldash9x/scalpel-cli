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
	cfg             config.Interface
	logger          *zap.Logger
	globalCtx       *core.GlobalContext
	adapterRegistry map[schemas.TaskType]core.Analyzer
}

// Option is a function that configures a MonolithicWorker.
type Option func(*MonolithicWorker)

// WithAnalyzers provides a way to inject a custom set of analyzers.
// This is primarily used for testing to replace real adapters with mocks.
func WithAnalyzers(analyzers map[schemas.TaskType]core.Analyzer) Option {
	return func(w *MonolithicWorker) {
		w.adapterRegistry = analyzers
	}
}

// NewMonolithicWorker initializes and returns a new worker instance.
// It accepts functional options for custom configuration, like injecting mock adapters for testing.
func NewMonolithicWorker(
	cfg config.Interface,
	logger *zap.Logger,
	globalCtx *core.GlobalContext,
	opts ...Option,
) (*MonolithicWorker, error) {

	w := &MonolithicWorker{
		cfg:             cfg,
		logger:          logger.With(zap.String("component", "worker")),
		globalCtx:       globalCtx,
		adapterRegistry: make(map[schemas.TaskType]core.Analyzer),
	}

	for _, opt := range opts {
		opt(w)
	}

	if len(w.adapterRegistry) == 0 {
		if err := w.registerAdapters(); err != nil {
			return nil, fmt.Errorf("failed to register default worker adapters: %w", err)
		}
	}

	return w, nil
}

// GlobalCtx provides safe, read-only access to the worker's global context.
func (w *MonolithicWorker) GlobalCtx() *core.GlobalContext {
	return w.globalCtx
}

// registerAdapters builds the map of task types to their corresponding analyzers.
// registerAdapters builds the map of task types to their corresponding analyzers.
func (w *MonolithicWorker) registerAdapters() error {
	// The ATO and IDOR adapters are now treated as stateless at construction,
	// just like the adapters below. They receive their context via the
	// Analyze method.
	w.adapterRegistry[schemas.TaskTestAuthATO] = adapters.NewATOAdapter()
	w.adapterRegistry[schemas.TaskTestAuthIDOR] = adapters.NewIDORAdapter()

	// STATELESS ADAPTERS: These constructors are simple and take no arguments.
	// They receive all context they need when their "Analyze" method is called.
	w.adapterRegistry[schemas.TaskAnalyzeWebPageTaint] = adapters.NewTaintAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeHeaders] = adapters.NewHeadersAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeJWT] = adapters.NewJWTAdapter()
	w.adapterRegistry[schemas.TaskAgentMission] = adapters.NewAgentAdapter()

	w.logger.Info("Default analyzer adapters registered", zap.Int("count", len(w.adapterRegistry)))
	return nil
}

// ProcessTask executes a single analysis task by delegating to the correct adapter.
func (w *MonolithicWorker) ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	task := analysisCtx.Task

	adapter, exists := w.adapterRegistry[task.Type]
	if !exists {
		return fmt.Errorf("no adapter registered for task type '%s'", task.Type)
	}

	analysisCtx.Logger.Info("Dispatching task to adapter", zap.String("adapter_name", adapter.Name()))

	if err := adapter.Analyze(ctx, analysisCtx); err != nil {
		return fmt.Errorf("adapter '%s' failed during analysis: %w", adapter.Name(), err)
	}

	analysisCtx.Logger.Info("Adapter finished analysis", zap.String("adapter_name", adapter.Name()))

	return nil
}
