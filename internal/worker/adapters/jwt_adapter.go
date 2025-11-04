// internal/worker/adapters/jwt_adapter.go
package adapters

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/static/jwt"
	"go.uber.org/zap"
)

// JWTAdapter acts as a bridge between the worker and the specific JWT static analyzer.
type JWTAdapter struct {
	// embedding the BaseAnalyzer provides default implementations for Name(), etc.
	core.BaseAnalyzer
}

// NewJWTAdapter creates a new adapter for JWT analysis.
func NewJWTAdapter() *JWTAdapter {
	return &JWTAdapter{
		// Add the missing *zap.Logger argument to the NewBaseAnalyzer call.
		BaseAnalyzer: *core.NewBaseAnalyzer("JWT Adapter", "Scans for common JWT vulnerabilities.", core.TypeStatic, zap.NewNop()),
	}
}

// Analyze is the main execution method for the adapter.
func (a *JWTAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	// The adapter's primary role is to correctly configure and
	// delegate the analysis task to the underlying analyzer.

	// extract the necessary configuration from the global context using the new contract.
	bruteForceEnabled := false
	if analysisCtx.Global != nil && analysisCtx.Global.Config != nil {
		jwtConfig := analysisCtx.Global.Config.JWT()
		// If the entire JWT scanner is disabled, we should stop here.
		if !jwtConfig.Enabled {
			return nil
		}
		bruteForceEnabled = jwtConfig.BruteForceEnabled
	}

	// instantiate the actual analyzer with the correct logger and configuration.
	analyzer := jwt.NewJWTAnalyzer(analysisCtx.Logger, bruteForceEnabled)

	// delegate the analysis call. the analyzer will add any findings
	// directly to the provided analysis context.
	return analyzer.Analyze(ctx, analysisCtx)
}
