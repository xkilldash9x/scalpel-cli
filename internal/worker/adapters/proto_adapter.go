// File: internal/worker/adapters/proto_adapter.go
package adapters

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"

	proto "github.com/xkilldash9x/scalpel-cli/internal/analysis/active/protopollution/analyze"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// ProtoAdapter bridges the generic worker framework and the specialized
// Prototype Pollution analyzer.
type ProtoAdapter struct {
	// The adapter itself is stateless; configuration and resources are provided
	// during the Analyze call via the AnalysisContext.
}

// NewProtoAdapter creates a new instance of the ProtoAdapter.
func NewProtoAdapter() *ProtoAdapter {
	return &ProtoAdapter{}
}

// Name returns the identifier for this adapter.
func (a *ProtoAdapter) Name() string {
	return "ProtoAdapter"
}

// Description returns a brief explanation of the adapter's purpose.
func (a *ProtoAdapter) Description() string {
	return "Analyzes web pages for prototype pollution vulnerabilities."
}

// Type returns the type of the analyzer.
func (a *ProtoAdapter) Type() core.AnalyzerType {
	return core.TypeActive
}

// Analyze executes the prototype pollution analysis task.
func (a *ProtoAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	// Add immediate context check to respect cancellation before any work.
	if err := ctx.Err(); err != nil {
		return err
	}

	task := analysisCtx.Task
	logger := analysisCtx.Logger

	// Accessing shared resources via the GlobalContext within the AnalysisContext.
	globalCtx := analysisCtx.Global

	if globalCtx == nil {
		return fmt.Errorf("GlobalContext is required but missing from AnalysisContext")
	}

	// 1. Input Validation
	if task.TargetURL == "" {
		return fmt.Errorf("TargetURL is required for %s", schemas.TaskAnalyzeWebPageProtoPP)
	}

	// 2. Resource Check
	if globalCtx.BrowserManager == nil {
		return fmt.Errorf("browser manager is required but not available")
	}

	// 3. Configuration Check
	if globalCtx.Config == nil {
		return fmt.Errorf("configuration is not available in the global context")
	}
	protoConfig := globalCtx.Config.Scanners().Active.ProtoPollution

	// Check if the specific scanner is enabled.
	if !protoConfig.Enabled {
		logger.Info("Skipping prototype pollution analysis as it is disabled in the configuration.")
		return nil
	}

	// 4. Initialize Analyzer
	// The proto.Analyzer is designed to be reusable and stateless.
	analyzer := proto.NewAnalyzer(
		logger.With(zap.String("module", proto.ModuleName)),
		globalCtx.BrowserManager,
		globalCtx.Config,
	)

	// 5. Execute Analysis
	logger.Info("Starting prototype pollution analysis",
		zap.String("target", task.TargetURL),
		zap.Duration("wait_duration", protoConfig.WaitDuration),
	)

	// The Analyze method handles session creation, execution, and finding reporting internally.
	if err := analyzer.Analyze(ctx, task.TaskID, task.TargetURL); err != nil {
		logger.Error("Prototype pollution analysis failed", zap.Error(err))
		return fmt.Errorf("failed to analyze target %s: %w", task.TargetURL, err)
	}

	logger.Info("Prototype pollution analysis completed.")
	return nil
}
