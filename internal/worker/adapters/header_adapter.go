// internal/worker/adapters/headers_adapter.go
package adapters

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/passive/headers"
)

/type HeadersAdapter struct {
	core.BaseAnalyzer
    // FIX: Changed from *passive.HeadersAnalyzer to *headers.HeadersAnalyzer
	headersAnalyzer *headers.HeadersAnalyzer
}

// NewHeadersAdapter creates a new adapter instance.
func NewHeadersAdapter() *HeadersAdapter {
	return &HeadersAdapter{
		// Give the adapter its own name for logging clarity.
		BaseAnalyzer:    core.NewBaseAnalyzer("Headers Adapter", core.TypePassive),
        // FIX: Changed from passive.NewHeadersAnalyzer() to headers.NewHeadersAnalyzer()
		headersAnalyzer: headers.NewHeadersAnalyzer(), // Creates an instance of the real analyzer.
	}
}

// Analyze is the bridge function called by the worker.
func (a *HeadersAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Dispatching to security headers analyzer.")

	// The beautiful part about good interface design is that sometimes,
	// the adapter just needs to pass the work along.
	return a.headersAnalyzer.Analyze(ctx, analysisCtx)
}
