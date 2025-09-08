// internal/worker/adapters/headers_adapter.go
package adapters

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/passive/headers"
)

// HeadersAdapter adapts the passive HeadersAnalyzer to be used by a generic worker.
// This is a pretty straightforward wrapper since the underlying analyzer's
// signature already matches what the worker expects.
type HeadersAdapter struct {
	core.BaseAnalyzer
	headersAnalyzer *passive.HeadersAnalyzer
}

// NewHeadersAdapter creates a new adapter instance.
func NewHeadersAdapter() *HeadersAdapter {
	return &HeadersAdapter{
		// Give the adapter its own name for logging clarity.
		BaseAnalyzer:    core.NewBaseAnalyzer("Headers Adapter", core.TypePassive),
		headersAnalyzer: passive.NewHeadersAnalyzer(), // Creates an instance of the real analyzer.
	}
}

// Analyze is the bridge function called by the worker.
func (a *HeadersAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Dispatching to security headers analyzer.")

	// The beautiful part about good interface design is that sometimes,
	// the adapter just needs to pass the work along.
	return a.headersAnalyzer.Analyze(ctx, analysisCtx)
}
