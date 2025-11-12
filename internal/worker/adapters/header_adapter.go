// internal/worker/adapters/headers_adapter.go
package adapters

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/passive/headers"
	"go.uber.org/zap"
)

type HeadersAdapter struct {
	core.BaseAnalyzer
	headersAnalyzer *headers.HeadersAnalyzer
}

// NewHeadersAdapter creates a new adapter instance.
func NewHeadersAdapter() *HeadersAdapter {
	return &HeadersAdapter{
		// Give the adapter its own name for logging clarity.
		// Dereference the pointer returned by NewBaseAnalyzer and provide all required arguments.
		BaseAnalyzer:    *core.NewBaseAnalyzer("Headers Adapter", "Analyzes security headers", core.TypePassive, zap.NewNop()),
		headersAnalyzer: headers.NewHeadersAnalyzer(), // Creates an instance of the real analyzer.
	}
}

// Analyze is the bridge function called by the worker.
func (a *HeadersAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Starting security headers analysis.")

	// The beautiful part about good interface design is that sometimes,
	// the adapter just needs to pass the work along.
	err := a.headersAnalyzer.Analyze(ctx, analysisCtx)

	analysisCtx.Logger.Info("Security headers analysis finished.")
	return err
}
