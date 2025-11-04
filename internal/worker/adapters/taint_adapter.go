// File: internal/worker/adapters/taint_adapter.go
package adapters

import (
	"context"
	"fmt"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/taint"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// TaintAdapter orchestrates the Interactive Application Security Testing (IAST) analysis.
type TaintAdapter struct {
	core.BaseAnalyzer
}

// NewTaintAdapter creates a new TaintAdapter.
func NewTaintAdapter() *TaintAdapter {
	return &TaintAdapter{
		BaseAnalyzer: *core.NewBaseAnalyzer("TaintAdapter_IAST_v1", "Performs IAST analysis by actively tainting inputs in a browser session and observing sensitive sinks.", core.TypeActive, zap.NewNop()),
	}
}

func (a *TaintAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))
	logger.Info("Initializing taint analysis (IAST)")

	// 1. Resource and Configuration Checks
	if analysisCtx.Global == nil || analysisCtx.Global.BrowserManager == nil {
		return fmt.Errorf("critical error: browser manager not initialized in global context")
	}

	// Configuration setup
	taintCfg, err := a.setupTaintConfig(analysisCtx)
	if err != nil {
		return fmt.Errorf("failed to setup taint configuration: %w", err)
	}

	// 2. Analyzer Initialization
	// The reporter bridges the analyzer's findings back to the analysis context.
	reporter := NewContextReporter(analysisCtx)
	// OAST provider might be nil if OAST is disabled, the analyzer should handle this.
	oastProvider := analysisCtx.Global.OASTProvider

	// The ContextReporter methods were renamed in the refactoring.
	// We adapt the interface here to match what taint.NewAnalyzer expects (taint.Reporter).
	taintReporterAdapter := &taintReporterAdapter{ContextReporter: reporter}

	analyzer, err := taint.NewAnalyzer(taintCfg, taintReporterAdapter, oastProvider, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize taint analyzer: %w", err)
	}

	// 3. Resource Acquisition (Browser Session)
	session, err := analysisCtx.Global.BrowserManager.NewAnalysisContext(
		ctx,
		analysisCtx.Task,
		schemas.DefaultPersona,
		"", // initialURL
		"", // initialData
		analysisCtx.Global.FindingsChan,
	)
	if err != nil {
		return fmt.Errorf("failed to create browser session for taint analysis: %w", err)
	}
	// Ensure the session is closed. Use background context for cleanup.
	defer session.Close(context.Background())

	// 4. Execution
	logger.Info("Starting taint analysis execution", zap.String("target_url", analysisCtx.TargetURL.String()))

	if err := analyzer.Analyze(ctx, session); err != nil {
		// Handle context cancellation gracefully.
		if ctx.Err() != nil {
			logger.Warn("Taint analysis interrupted or timed out", zap.Error(err))
			// Return the context error so the worker framework understands the reason for termination.
			return ctx.Err()
		}
		return fmt.Errorf("taint analysis failed during execution: %w", err)
	}

	logger.Info("Taint analysis execution completed")
	return nil
}

// setupTaintConfig gathers configuration from the global context and sets up the specific taint.Config struct.
func (a *TaintAdapter) setupTaintConfig(analysisCtx *core.AnalysisContext) (taint.Config, error) {
	if analysisCtx.Global.Config == nil {
		return taint.Config{}, fmt.Errorf("global configuration is missing")
	}

	if analysisCtx.TargetURL == nil {
		return taint.Config{}, fmt.Errorf("TargetURL is missing in AnalysisContext")
	}

	globalCfg := analysisCtx.Global.Config
	scannerCfg := globalCfg.Scanners().Active.Taint
	engineCfg := globalCfg.Engine()

	// Define default values for timings and buffers.
	const (
		defaultEventBuffer         = 500
		defaultFinalizationGrace   = 5 * time.Second
		defaultProbeExpiration     = 5 * time.Minute
		defaultCleanupInterval     = 1 * time.Minute
		defaultOASTPollingInterval = 20 * time.Second
	)

	return taint.Config{
		TaskID:                  analysisCtx.Task.TaskID,
		Target:                  analysisCtx.TargetURL,
		Probes:                  taint.DefaultProbes(), // Use standard probes.
		Sinks:                   taint.DefaultSinks(),  // Monitor standard sinks.
		AnalysisTimeout:         engineCfg.DefaultTaskTimeout,
		EventChannelBuffer:      defaultEventBuffer,
		FinalizationGracePeriod: defaultFinalizationGrace,
		ProbeExpirationDuration: defaultProbeExpiration,
		CleanupInterval:         defaultCleanupInterval,
		OASTPollingInterval:     defaultOASTPollingInterval,
		Interaction: schemas.InteractionConfig{
			MaxDepth: scannerCfg.Depth, // Use the configured crawl depth for interaction.
		},
	}, nil
}

// taintReporterAdapter adapts the refactored ContextReporter (which uses ReportTaintFinding)
// to the taint.Reporter interface (which expects a Report method).
type taintReporterAdapter struct {
	*ContextReporter
}

func (a *taintReporterAdapter) Report(finding taint.CorrelatedFinding) {
	a.ReportTaintFinding(finding)
}
