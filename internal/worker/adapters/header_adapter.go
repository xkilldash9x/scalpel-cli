// File: internal/worker/adapters/headers_adapter.go
package adapters

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/passive/headers"
	"go.uber.org/zap"
)

// AnalyzerInterface defines the contract for the underlying analyzer logic.
// This allows for mocking in tests and decouples the adapter from the implementation.
//
//go:generate mockery --name AnalyzerInterface --output ../../../internal/mocks --outpkg mocks --structname MockHeadersAnalyzer
type AnalyzerInterface interface {
	Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error
}

// HeadersAdapter bridges the worker framework and the passive security headers analyzer.
type HeadersAdapter struct {
	core.BaseAnalyzer
	// Holds the instance of the analyzer logic, now using the interface for testability.
	headersAnalyzer AnalyzerInterface
}

// NewHeadersAdapter creates a new adapter instance using the default concrete implementation.
func NewHeadersAdapter() *HeadersAdapter {
	// Initialize the default analyzer.
	return NewHeadersAdapterWithAnalyzer(headers.NewHeadersAnalyzer())
}

// NewHeadersAdapterWithAnalyzer allows injecting a specific analyzer implementation (primarily for testing).
func NewHeadersAdapterWithAnalyzer(analyzer AnalyzerInterface) *HeadersAdapter {
	return &HeadersAdapter{
		// Initialize the BaseAnalyzer with metadata.
		BaseAnalyzer: *core.NewBaseAnalyzer("Headers Adapter", "Analyzes HTTP response headers for security best practices and information disclosure.", core.TypePassive, zap.NewNop()),
		// Use the injected analyzer.
		headersAnalyzer: analyzer,
	}
}

// Analyze is the bridge function called by the worker.
func (a *HeadersAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))
	logger.Debug("Dispatching to security headers analyzer.")

	// The adapter simply delegates the call to the underlying analyzer.
	// The headersAnalyzer will use the Artifacts (HAR data) in the analysisCtx
	// and add findings directly to the context.
	return a.headersAnalyzer.Analyze(ctx, analysisCtx)
}
