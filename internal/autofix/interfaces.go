
// internal/autofix/interfaces.go
package autofix

import (
	"context"
)

// WatcherInterface defines the contract for a component that monitors for
// application crashes and generates post-mortem reports.
type WatcherInterface interface {
	// Start begins the monitoring process. It is a blocking call that should be
	// run in a separate goroutine.
	Start(ctx context.Context) error
}

// AnalyzerInterface defines the contract for a component that can analyze a
// crash report and generate a potential fix.
type AnalyzerInterface interface {
	// GeneratePatch takes a post-mortem report and returns a structured analysis
	// result, including a proposed patch.
	GeneratePatch(ctx context.Context, report PostMortem) (*AnalysisResult, error)
}

// DeveloperInterface defines the contract for a component that can validate a
// proposed patch and, if successful, commit it and create a pull request.
type DeveloperInterface interface {
	// ValidateAndCommit takes a post-mortem report and an analysis result,
	// then orchestrates the TDD validation cycle and Git workflow.
	ValidateAndCommit(ctx context.Context, report PostMortem, analysis *AnalysisResult) error
}
