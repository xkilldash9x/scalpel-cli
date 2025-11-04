// File: internal/worker/adapters/proto_adapter.go
package adapters

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"

	proto "github.com/xkilldash9x/scalpel-cli/internal/analysis/active/protopollution/analyze"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// ProtoAdapter bridges the generic worker framework and the specialized
// Prototype Pollution analyzer.
type ProtoAdapter struct {
	// Embed BaseAnalyzer for consistency and metadata management.
	core.BaseAnalyzer
}

// NewProtoAdapter creates a new instance of the ProtoAdapter.
func NewProtoAdapter() *ProtoAdapter {
	return &ProtoAdapter{
		BaseAnalyzer: *core.NewBaseAnalyzer(
			"ProtoAdapter",
			"Analyzes web pages for client-side prototype pollution vulnerabilities using active browser instrumentation.",
			core.TypeActive,
			zap.NewNop(),
		),
	}
}

// Analyze executes the prototype pollution analysis task.
func (a *ProtoAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	// Add immediate context check to respect cancellation before any work.
	if err := ctx.Err(); err != nil {
		return err
	}

	task := analysisCtx.Task
	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))

	// 1. Input Validation
	if task.TargetURL == "" {
		return fmt.Errorf("TargetURL is required for %s", schemas.TaskAnalyzeWebPageProtoPP)
	}

	// 2. Resource and Configuration Checks
	globalCtx := analysisCtx.Global
	if globalCtx == nil {
		return fmt.Errorf("GlobalContext is required but missing from AnalysisContext")
	}

	if globalCtx.BrowserManager == nil {
		return fmt.Errorf("browser manager is required but not available")
	}

	protoConfig, err := a.getConfiguration(globalCtx)
	if err != nil {
		return err
	}

	// Check if the specific scanner is enabled.
	if !protoConfig.Enabled {
		logger.Info("Skipping prototype pollution analysis as it is disabled in the configuration.")
		return nil
	}

	// 3. Initialize Analyzer
	// The proto.Analyzer manages its own browser sessions via the BrowserManager.
	analyzer := proto.NewAnalyzer(
		// Use the adapter's logger, ensuring the module name matches the underlying analyzer's expectation.
		logger.With(zap.String("module", proto.ModuleName)),
		globalCtx.BrowserManager,
		protoConfig,
	)

	// 4. Execute Analysis
	logger.Info("Starting prototype pollution analysis",
		zap.String("target", task.TargetURL),
		zap.Duration("wait_duration", protoConfig.WaitDuration),
	)

	// The underlying Analyze method handles the entire process.
	if err := analyzer.Analyze(ctx, task.TaskID, task.TargetURL); err != nil {
		// Check if the failure was due to context cancellation.
		if ctx.Err() != nil {
			logger.Warn("Prototype pollution analysis interrupted or timed out.", zap.Error(err))
			return ctx.Err()
		}
		logger.Error("Prototype pollution analysis failed", zap.Error(err))
		return fmt.Errorf("failed to analyze target %s: %w", task.TargetURL, err)
	}

	logger.Info("Prototype pollution analysis completed.")
	return nil
}

// getConfiguration safely retrieves the ProtoPollution configuration from the GlobalContext.
func (a *ProtoAdapter) getConfiguration(globalCtx *core.GlobalContext) (config.ProtoPollutionConfig, error) {
	if globalCtx.Config == nil {
		return config.ProtoPollutionConfig{}, fmt.Errorf("configuration is not available in the global context")
	}
	return globalCtx.Config.Scanners().Active.ProtoPollution, nil
}
