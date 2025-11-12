package core

import (
	"context"

	"go.uber.org/zap"
)

// AnalyzerType distinguishes between passive and active analysis modules.
type AnalyzerType string

const (
	// TypeActive analyzers interact with the target application.
	TypeActive AnalyzerType = "ACTIVE"
	// TypePassive analyzers only inspect artifacts (HAR, DOM, etc.).
	TypePassive AnalyzerType = "PASSIVE"
	// TypeStatic is a more descriptive alias for passive analysis.
	// Static analysis, by its nature, operates on collected data without direct interaction.
	TypeStatic AnalyzerType = "STATIC"
	// TypeAgent analyzers are for autonomous agent missions.
	TypeAgent AnalyzerType = "AGENT"
)

// Analyzer is the core interface that all security analysis modules must
// implement. It defines the standard contract for how the analysis engine
// interacts with a specific scanner, regardless of whether it's active, passive,
// or static.
type Analyzer interface {
	Name() string
	Description() string
	Type() AnalyzerType
	Analyze(ctx context.Context, analysisCtx *AnalysisContext) error
}

// BaseAnalyzer provides a foundational implementation of the `Analyzer` interface,
// handling common fields like name, description, and type. It is intended to be
// embedded within specific analyzer implementations to reduce boilerplate code.
type BaseAnalyzer struct {
	name         string
	description  string
	analyzerType AnalyzerType
	Logger       *zap.Logger // Exposed for use in specific analyzer implementations.
}

// NewBaseAnalyzer creates and initializes a new BaseAnalyzer, which can be
// embedded in other analyzer structs to provide default implementations of the
// Analyzer interface methods.
func NewBaseAnalyzer(name, description string, analyzerType AnalyzerType, logger *zap.Logger) *BaseAnalyzer {
	return &BaseAnalyzer{
		name:         name,
		description:  description,
		analyzerType: analyzerType,
		Logger:       logger.Named(name), // Automatically create a named sub-logger.
	}
}

// Name returns the analyzer's name.
func (b *BaseAnalyzer) Name() string {
	return b.name
}

// Description returns the analyzer's description.
func (b *BaseAnalyzer) Description() string {
	return b.description
}

// Type returns the analyzer's type (e.g., ACTIVE, PASSIVE).
func (b *BaseAnalyzer) Type() AnalyzerType {
	return b.analyzerType
}
