package core

import (
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
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

// BaseAnalyzer provides foundational fields and methods for all analysis modules.
// It is intended to be embedded in specific analyzer implementations.
type BaseAnalyzer struct {
	name         string
	description  string
	analyzerType AnalyzerType
	// Logger is exposed so implementing analyzers can use a structured logger.
	Logger *zap.Logger
}

// NewBaseAnalyzer creates a new BaseAnalyzer instance.
func NewBaseAnalyzer(name, description string, analyzerType AnalyzerType, logger *zap.Logger) *BaseAnalyzer {
	// If no logger is provided, fall back to the global logger.
	// This prevents components from being initialized with a no-op logger by default.
	if logger == nil {
		logger = observability.GetLogger()
	}
	return &BaseAnalyzer{
		name:         name,
		description:  description,
		analyzerType: analyzerType,
		// Automatically name the logger based on the analyzer name.
		Logger: logger.Named(name),
	}
}

// Name returns the name of the analyzer.
func (b *BaseAnalyzer) Name() string {
	return b.name
}

// Description returns the description of the analyzer.
func (b *BaseAnalyzer) Description() string {
	return b.description
}

// Type returns the type of the analyzer (Active/Passive).
func (b *BaseAnalyzer) Type() AnalyzerType {
	return b.analyzerType
}
