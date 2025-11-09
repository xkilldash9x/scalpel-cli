
// internal/autofix/interfaces.go
package autofix

import (
	"context"
)

// WatcherInterface defines the contract for the crash detection and reporting component.
type WatcherInterface interface {
	Start(ctx context.Context) error
}

// AnalyzerInterface defines the contract for the analysis and patch generation component.
type AnalyzerInterface interface {
	GeneratePatch(ctx context.Context, report PostMortem) (*AnalysisResult, error)
}

// DeveloperInterface defines the contract for the validation and commit component.
type DeveloperInterface interface {
	ValidateAndCommit(ctx context.Context, report PostMortem, analysis *AnalysisResult) error
}
