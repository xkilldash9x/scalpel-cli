// internal/worker/adapters/taint_adapter.go --
package adapters

import (
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/taint"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

type TaintAdapter struct {
	core.BaseAnalyzer
}

func NewTaintAdapter() *TaintAdapter {
	return &TaintAdapter{
		BaseAnalyzer: core.NewBaseAnalyzer("TaintAdapter_IAST_v1", core.TypeActive),
	}
}

func (a *TaintAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))
	logger.Info("Initializing taint analysis")

	// CORRECTED: Use the simplified BrowserManager to get a session.
	if analysisCtx.Global.BrowserManager == nil {
		return fmt.Errorf("critical error: browser manager not initialized in global context")
	}
	session, err := analysisCtx.Global.BrowserManager.InitializeSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize browser session: %w", err)
	}
	defer session.Close(ctx) // Ensures the browser tab is always closed.
	logger.Debug("Browser session initialized")

	reporter := NewContextReporter(analysisCtx)
	
	// Translate global config and task params into the specific Taint configuration.
	cfg := analysisCtx.Global.Config.Scanners.Active.Taint
	taintConfig := taint.Config{
		TaskID:                  analysisCtx.Task.TaskID,
		Target:                  analysisCtx.TargetURL,
		Probes:                  taint.GenerateProbes(),
		Sinks:                   taint.GenerateSinks(),
		AnalysisTimeout:         analysisCtx.Global.Config.Engine.DefaultTaskTimeout,
		EventChannelBuffer:      500,
		FinalizationGracePeriod: 5 * time.Second,
		ProbeExpirationDuration: 5 * time.Minute,
		CleanupInterval:         1 * time.Minute,
		Interaction: taint.InteractionConfig{
			MaxDepth: cfg.Depth,
		},
	}

	analyzer, err := taint.NewAnalyzer(taintConfig, session, reporter, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize taint analyzer: %w", err)
	}

	logger.Info("Starting taint analysis execution", zap.String("target_url", analysisCtx.TargetURL.String()))
	if err := analyzer.Analyze(ctx); err != nil {
		if ctx.Err() != nil {
			logger.Warn("Taint analysis interrupted or timed out", zap.Error(err))
			return nil // Don't treat context cancellation as a fatal task error
		}
		return fmt.Errorf("taint analysis failed during execution: %w", err)
	}

	logger.Info("Taint analysis execution completed")
	return nil
}
