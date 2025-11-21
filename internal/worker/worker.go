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

// HumanoidInterface defines the methods that a humanoid instance must implement.
type HumanoidInterface interface {
	MoveTo(ctx context.Context, selector string, opts *humanoid.InteractionOptions) error
	IntelligentClick(ctx context.Context, selector string, opts *humanoid.InteractionOptions) error
	Type(ctx context.Context, selector, text string, opts *humanoid.InteractionOptions) error
	DragAndDrop(ctx context.Context, startSelector, endSelector string, opts *humanoid.InteractionOptions) error
	CognitivePause(ctx context.Context, meanScale, stdDevScale float64) error
}

// MonolithicWorker processes tasks in-process.
// It serves as a central dispatcher, routing analysis tasks to the appropriate,
// specialized adapters based on the task type.
type MonolithicWorker struct {
	cfg       config.Interface
	logger    *zap.Logger
	globalCtx *core.GlobalContext
	// MODIFIED: Use the centralized type definition
	adapterRegistry core.AdapterRegistry
}

// Option is a function that configures a MonolithicWorker.
type Option func(*MonolithicWorker)

// WithAnalyzers provides a way to inject a custom set of analyzers.
// MODIFIED: Use the centralized type definition
func WithAnalyzers(analyzers core.AdapterRegistry) Option {
	return func(w *MonolithicWorker) {
		w.adapterRegistry = analyzers
	}
}

// remarshalParams is a utility function to convert the generic interface{} parameters
// into a specific struct type.
func remarshalParams(params interface{}, v interface{}) error {
	if params == nil {
		return nil
	}
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal parameters: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal parameters into target struct (%T): %w", v, err)
	}
	return nil
}

// NewMonolithicWorker initializes and returns a new worker instance.
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
		adapterRegistry: make(core.AdapterRegistry),
	}

	for _, opt := range opts {
		opt(w)
	}

	if len(w.adapterRegistry) == 0 {
		if err := w.registerAdapters(); err != nil {
			return nil, fmt.Errorf("failed to register default worker adapters: %w", err)
		}
	}

	// FIX (Bug 1: Adapter Sync): Ensure the GlobalContext reflects the initialized adapters.
	// Go maps cannot be compared directly with !=. We unconditionally synchronize
	// here to ensure the GlobalContext points to the authoritative registry instance
	// managed by this worker.
	w.globalCtx.Adapters = w.adapterRegistry
	w.logger.Debug("Synchronized adapter registry with GlobalContext")

	return w, nil
}

// GlobalCtx provides safe, read-only access to the worker's global context.
func (w *MonolithicWorker) GlobalCtx() *core.GlobalContext {
	return w.globalCtx
}

// registerAdapters builds the map of task types to their corresponding analyzers.
func (w *MonolithicWorker) registerAdapters() error {
	// The ATO and IDOR adapters are now treated as stateless at construction.
	w.adapterRegistry[schemas.TaskTestAuthATO] = adapters.NewATOAdapter()
	w.adapterRegistry[schemas.TaskTestAuthIDOR] = adapters.NewIDORAdapter()

	// STATELESS ADAPTERS
	w.adapterRegistry[schemas.TaskAnalyzeWebPageTaint] = adapters.NewTaintAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeWebPageProtoPP] = adapters.NewProtoAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeHeaders] = adapters.NewHeadersAdapter()
	w.adapterRegistry[schemas.TaskAnalyzeJWT] = adapters.NewJWTAdapter()
	w.adapterRegistry[schemas.TaskTestRaceCondition] = adapters.NewTimeslipAdapter()
	w.adapterRegistry[schemas.TaskAgentMission] = adapters.NewAgentAdapter()

	w.logger.Info("Default analyzer adapters registered", zap.Int("count", len(w.adapterRegistry)))
	return nil
}

// ProcessTask executes a single analysis task.
func (w *MonolithicWorker) ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	task := analysisCtx.Task

	// Direct Dispatch for specialized tasks like Humanoid Sequences
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

	var params schemas.HumanoidSequenceParams
	if err := remarshalParams(task.Parameters, &params); err != nil {
		return fmt.Errorf("invalid parameters for HUMANOID_SEQUENCE: %w", err)
	}

	if len(params.Steps) == 0 {
		logger.Info("HUMANOID_SEQUENCE task received with zero steps, skipping.")
		return nil
	}

	// FIX (Bug 2: Missing TargetURL): Validate that TargetURL is present if steps are provided.
	if task.TargetURL == "" {
		return fmt.Errorf("TargetURL is required for HUMANOID_SEQUENCE when steps are provided")
	}

	persona := schemas.DefaultPersona
	if params.Persona != nil {
		persona = *params.Persona
		logger.Debug("Using overridden persona for humanoid sequence", zap.String("UserAgent", persona.UserAgent))
	}

	browserManager := w.globalCtx.BrowserManager
	if browserManager == nil {
		return fmt.Errorf("browser manager is not available in global context")
	}

	// FIX (Bug 3: Taint Config Ignored): Pass the TaintTemplate and TaintConfig from the parameters.
	sessionCtx, err := browserManager.NewAnalysisContext(
		ctx,
		w.cfg,
		persona,
		params.TaintTemplate, // Use template from params
		params.TaintConfig,   // Use config from params
		w.globalCtx.FindingsChan,
	)
	if err != nil {
		return fmt.Errorf("failed to create browser session for humanoid task: %w", err)
	}

	// FIX (Bug 4: Missing Session Assignment): Ensure the analysis context reflects the newly created session.
	analysisCtx.Session = sessionCtx

	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if closeErr := sessionCtx.Close(cleanupCtx); closeErr != nil {
			logger.Warn("Failed to close browser session cleanly after humanoid task", zap.Error(closeErr))
		}
	}()

	// Navigation is unconditional now due to the validation (Bug 2).
	logger.Debug("Navigating to initial TargetURL", zap.String("url", task.TargetURL))
	if err := sessionCtx.Navigate(ctx, task.TargetURL); err != nil {
		return fmt.Errorf("failed to navigate to initial TargetURL %s: %w", task.TargetURL, err)
	}

	h := humanoid.New(w.cfg.Browser().Humanoid, logger.With(zap.String("component", "humanoid")), sessionCtx)
	if err := w.executeHumanoidSteps(ctx, h, params.Steps); err != nil {
		return fmt.Errorf("failed during humanoid sequence execution: %w", err)
	}

	return nil
}

// executeHumanoidSteps iterates through the steps and dispatches them to the controller.
func (w *MonolithicWorker) executeHumanoidSteps(ctx context.Context, h HumanoidInterface, steps []schemas.HumanoidStep) error {
	for i, step := range steps {
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
			meanScale := step.MeanScale
			if meanScale <= 0 {
				meanScale = 1.0
			}
			stdDevScale := step.StdDevScale
			if stdDevScale <= 0 {
				stdDevScale = 1.0
			}
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
func convertHumanoidOptions(schemaOpts *schemas.HumanoidInteractionOptions) (*humanoid.InteractionOptions, error) {
	if schemaOpts == nil {
		return nil, nil
	}

	opts := &humanoid.InteractionOptions{
		EnsureVisible: schemaOpts.EnsureVisible,
	}

	if len(schemaOpts.FieldSources) > 0 {
		field := humanoid.NewPotentialField()
		for _, source := range schemaOpts.FieldSources {
			pos := humanoid.Vector2D{X: source.PositionX, Y: source.PositionY}
			field.AddSource(pos, source.Strength, source.Falloff)
		}
		opts.Field = field
	}

	return opts, nil
}
