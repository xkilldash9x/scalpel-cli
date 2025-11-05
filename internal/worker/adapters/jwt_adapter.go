// File: internal/worker/adapters/jwt_adapter.go
package adapters

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/static/jwt"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// JWTAdapter acts as a bridge between the worker and the specific JWT static analyzer.
type JWTAdapter struct {
	// Embedding the BaseAnalyzer provides default implementations for Name(), etc.
	core.BaseAnalyzer
}

// NewJWTAdapter creates a new adapter for JWT analysis.
func NewJWTAdapter() *JWTAdapter {
	return &JWTAdapter{
		// Pass nil for the logger; it will be retrieved from the AnalysisContext during Analyze.
		// This prevents issues with global logger initialization order.
		BaseAnalyzer: *core.NewBaseAnalyzer("JWT Adapter", "Scans artifacts (e.g., HAR files) for JWTs and analyzes them for common vulnerabilities.", core.TypeStatic, nil),
	}
}

// Analyze is the main execution method for the adapter.
func (a *JWTAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))

	// 1. Configuration Retrieval
	jwtConfig := a.getConfiguration(analysisCtx.Global)

	// 2. Check if the scanner is enabled.
	if !jwtConfig.Enabled {
		logger.Debug("Skipping JWT analysis as it is disabled in the configuration.")
		return nil
	}

	// 3. Analyzer Initialization
	// Instantiate the actual analyzer with the correct logger and configuration flags.
	analyzer := jwt.NewJWTAnalyzer(logger, jwtConfig.BruteForceEnabled)

	// 4. Execution Delegation
	logger.Debug("Starting JWT analysis.", zap.Bool("brute_force_enabled", jwtConfig.BruteForceEnabled))

	// The analyzer will use the Artifacts (HAR data) in the analysisCtx
	// and add findings directly to the context.
	if err := analyzer.Analyze(ctx, analysisCtx); err != nil {
		// The underlying analyzer handles artifact parsing errors. We just report the failure.
		logger.Error("JWT analysis failed.", zap.Error(err))
		return err
	}

	logger.Debug("JWT analysis completed.")
	return nil
}

// getConfiguration safely retrieves the JWT configuration from the GlobalContext.
func (a *JWTAdapter) getConfiguration(globalCtx *core.GlobalContext) config.JWTConfig {
	// Provide safe defaults if the context or config is missing.
	if globalCtx == nil || globalCtx.Config == nil {
		// Return a disabled configuration if the main config isn't available to be safe.
		return config.JWTConfig{Enabled: false}
	}
	return globalCtx.Config.JWT()
}
