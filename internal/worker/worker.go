// File: internal/worker/worker.go
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
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

// remarshalParams is a utility function to convert the generic interface{} parameters
// (often a map[string]interface{} from JSON) into a specific struct type using JSON marshaling/unmarshaling.
func remarshalParams(params interface{}, v interface{}) error {
	if params == nil {
		return nil
	}
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal parameters: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		// Including the type name improves debuggability.
		return fmt.Errorf("failed to unmarshal parameters into target struct (%T): %w", v, err)
	}
	return nil
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
func (w *MonolithicWorker) registerAdapters() error {
	// The ATO and IDOR adapters are now treated as stateless at construction,
	// just like the adapters below. They receive their context via the
	// Analyze method.
	w.adapterRegistry[schemas.TaskTestAuthATO] = adapters.NewATOAdapter()
	w.adapterRegistry[schemas.TaskTestAuthIDOR] = adapters.NewIDORAdapter()

	// STATELESS ADAPTERS: These constructors are simple and take no arguments.
	// They receive all context they need when their "Analyze" method is called.
	w.adapterRegistry[schemas.TaskAnalyzeWebPageTaint] = adapters.NewTaintAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeWebPageProtoPP] = adapters.NewProtoAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeHeaders] = adapters.NewHeadersAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeJWT] = adapters.NewJWTAdapter()
	w.adapterRegistry[schemas.TaskAgentMission] = adapters.NewAgentAdapter()

	w.logger.Info("Default analyzer adapters registered", zap.Int("count", len(w.adapterRegistry)))
	return nil
}

// ProcessTask executes a single analysis task by delegating to the correct adapter or handling it directly.
func (w *MonolithicWorker) ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	task := analysisCtx.Task

	// Direct Dispatch for specialized tasks (like Humanoid Sequences)
	switch task.Type {
	case schemas.TaskHumanoidSequence:
		analysisCtx.Logger.Info("Dispatching task directly", zap.String("handler", "processHumanoidTask"))
		if err := w.processHumanoidTask(ctx, analysisCtx); err != nil {
			return fmt.Errorf("handler 'processHumanoidTask' failed: %w", err)
		}
		analysisCtx.Logger.Info("Direct handler finished", zap.String("handler", "processHumanoidTask"))
		return nil
	}

	// Fallback to Adapter Registry for standard analysis tasks
	adapter, exists := w.adapterRegistry[task.Type]
	if !exists {
		// Update error message to reflect both possibilities.
		return fmt.Errorf("no adapter or direct handler registered for task type '%s'", task.Type)
	}

	analysisCtx.Logger.Info("Dispatching task to adapter", zap.String("adapter_name", adapter.Name()))

	if err := adapter.Analyze(ctx, analysisCtx); err != nil {
		return fmt.Errorf("adapter '%s' failed during analysis: %w", adapter.Name(), err)
	}

	analysisCtx.Logger.Info("Adapter finished analysis", zap.String("adapter_name", adapter.Name()))

	return nil
}

// processHumanoidTask handles the execution of a HUMANOID_SEQUENCE task.
func (w *MonolithicWorker) processHumanoidTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	task := analysisCtx.Task
	logger := analysisCtx.Logger

	// 1. Unmarshal Parameters
	var params schemas.HumanoidSequenceParams
	if err := remarshalParams(task.Parameters, &params); err != nil {
		return fmt.Errorf("invalid parameters for HUMANOID_SEQUENCE: %w", err)
	}

	if len(params.Steps) == 0 {
		logger.Info("HUMANOID_SEQUENCE task received with zero steps, skipping.")
		return nil
	}

	// 2. Determine Persona (Improvement: allows per-task override)
	persona := schemas.DefaultPersona
	if params.Persona != nil {
		persona = *params.Persona
		logger.Debug("Using overridden persona for humanoid sequence", zap.String("UserAgent", persona.UserAgent))
	}

	// 3. Acquire Browser Session
	browserManager := w.globalCtx.BrowserManager
	if browserManager == nil {
		return fmt.Errorf("browser manager is not available in global context")
	}

	// Create a new session (SessionContext) using the determined persona.
	// Taint configuration is omitted as it's not required for pure interaction simulation.
	sessionCtx, err := browserManager.NewAnalysisContext(
		ctx,
		w.cfg, // Pass the main configuration
		persona,
		"", // taintTemplate
		"", // taintConfig
		w.globalCtx.FindingsChan,
	)
	if err != nil {
		return fmt.Errorf("failed to create browser session for humanoid task: %w", err)
	}
	// Ensure the session is closed after the sequence completes.
	// Improvement (Robustness): Use a separate context with a timeout for cleanup.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if closeErr := sessionCtx.Close(cleanupCtx); closeErr != nil {
			logger.Warn("Failed to close browser session cleanly after humanoid task", zap.Error(closeErr))
		}
	}()

	// 4. Initial Navigation (if required by Task definition)
	if task.TargetURL != "" {
		logger.Debug("Navigating to initial TargetURL", zap.String("url", task.TargetURL))
		if err := sessionCtx.Navigate(ctx, task.TargetURL); err != nil {
			// Navigation failure often prevents further interaction.
			return fmt.Errorf("failed to navigate to initial TargetURL %s: %w", task.TargetURL, err)
		}
	}

	// 5. Initialize Humanoid Controller
	// The sessionCtx implements the humanoid.Executor interface.
	h := humanoid.New(w.cfg.Browser().Humanoid, logger.With(zap.String("component", "humanoid")), sessionCtx)
	// 6. Execute Sequence
	if err := w.executeHumanoidSteps(ctx, h, params.Steps); err != nil {
		return fmt.Errorf("failed during humanoid sequence execution: %w", err)
	}

	return nil
}

// executeHumanoidSteps iterates through the steps and dispatches them to the controller.
// We accept the concrete *humanoid.Humanoid type as the controller.
func (w *MonolithicWorker) executeHumanoidSteps(ctx context.Context, h *humanoid.Humanoid, steps []schemas.HumanoidStep) error {
	for i, step := range steps {
		// Convert schema options to internal humanoid options
		opts, err := convertHumanoidOptions(step.Options)
		if err != nil {
			return fmt.Errorf("step %d: failed to convert options: %w", i+1, err)
		}

		switch step.Action {
		case schemas.HumanoidMove:
			if step.Selector == "" {
				return fmt.Errorf("step %d (MOVE): selector is required", i+1)
			}
			if err := h.MoveTo(ctx, step.Selector, opts); err != nil {
				return fmt.Errorf("step %d (MOVE): %w", i+1, err)
			}
		case schemas.HumanoidClick:
			if step.Selector == "" {
				return fmt.Errorf("step %d (CLICK): selector is required", i+1)
			}
			if err := h.IntelligentClick(ctx, step.Selector, opts); err != nil {
				return fmt.Errorf("step %d (CLICK): %w", i+1, err)
			}
		case schemas.HumanoidType:
			if step.Selector == "" {
				return fmt.Errorf("step %d (TYPE): selector is required", i+1)
			}
			// Text can technically be empty, though unusual.
			if err := h.Type(ctx, step.Selector, step.Text, opts); err != nil {
				return fmt.Errorf("step %d (TYPE): %w", i+1, err)
			}
		case schemas.HumanoidDragDrop:
			if step.Selector == "" || step.EndSelector == "" {
				return fmt.Errorf("step %d (DRAG_DROP): selector (start) and end_selector are required", i+1)
			}
			if err := h.DragAndDrop(ctx, step.Selector, step.EndSelector, opts); err != nil {
				return fmt.Errorf("step %d (DRAG_DROP): %w", i+1, err)
			}
		case schemas.HumanoidPause:
			// Default scales if not provided or invalid
			meanScale := step.MeanScale
			if meanScale <= 0 {
				meanScale = 1.0
			}
			stdDevScale := step.StdDevScale
			if stdDevScale <= 0 {
				stdDevScale = 1.0
			}
			// Pause does not use InteractionOptions
			if err := h.CognitivePause(ctx, meanScale, stdDevScale); err != nil {
				return fmt.Errorf("step %d (PAUSE): %w", i+1, err)
			}
		default:
			return fmt.Errorf("step %d: unknown humanoid action type '%s'", i+1, step.Action)
		}
	}
	return nil
}

// convertHumanoidOptions converts the serializable schema options to the internal humanoid options.
// This mapping is necessary because the internal humanoid package uses specialized types (like Vector2D)
// that are not directly used in the transport schema.
func convertHumanoidOptions(schemaOpts *schemas.HumanoidInteractionOptions) (*humanoid.InteractionOptions, error) {
	if schemaOpts == nil {
		return nil, nil
	}

	opts := &humanoid.InteractionOptions{
		EnsureVisible: schemaOpts.EnsureVisible,
	}

	// Reconstruct the PotentialField from the serialized sources.
	if len(schemaOpts.FieldSources) > 0 {
		field := humanoid.NewPotentialField()
		for _, source := range schemaOpts.FieldSources {
			// Convert coordinates from schema format (X/Y fields) to internal Vector2D.
			pos := humanoid.Vector2D{X: source.PositionX, Y: source.PositionY}
			field.AddSource(pos, source.Strength, source.Falloff)
		}
		opts.Field = field
	}

	return opts, nil
}
