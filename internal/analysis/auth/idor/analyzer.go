// File: internal/analysis/auth/idor/analyzer.go
package idor

import (
	"context"
	"runtime"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// IDORAnalyzer implements the Analyzer interface and orchestrates the IDOR detection process.
type IDORAnalyzer struct {
	logger *zap.Logger
	// comparer is the injected service used for semantic comparison of responses.
	comparer jsoncompare.JSONComparison
}

// NewIDORAnalyzer creates and returns a new instance of the IDORAnalyzer.
// It requires a zap logger and an implementation of the JSONComparison interface.
func NewIDORAnalyzer(logger *zap.Logger, comparer jsoncompare.JSONComparison) Analyzer {
	if logger == nil {
		logger = observability.GetLogger()
	}
	// Ensure the comparer is provided.
	if comparer == nil {
		logger.Warn("JSONComparer not injected into IDORAnalyzer, initializing default service.")
		comparer = jsoncompare.NewService(logger)
	}

	return &IDORAnalyzer{
		logger:   logger,
		comparer: comparer,
	}
}

// AnalyzeTraffic is the main entry point for the analysis logic.
func (a *IDORAnalyzer) AnalyzeTraffic(ctx context.Context, traffic []RequestResponsePair, config Config) ([]Finding, error) {
	a.logger.Info("Starting IDOR analysis...")

	// 1. Validation and Setup
	if len(traffic) == 0 {
		a.logger.Info("No traffic provided to analyze.")
		return nil, nil
	}

	// Validate configuration and set production-ready defaults.
	if err := a.validateAndConfigure(&config); err != nil {
		return nil, err
	}

	// 2. Execute Detection Logic
	// Pass the injected logger and comparer service to the detection logic.
	findings, err := Detect(ctx, traffic, config, a.logger.Sugar(), a.comparer)
	if err != nil {
		// Check if the error is due to context cancellation.
		if ctx.Err() != nil {
			a.logger.Warn("IDOR analysis cancelled or timed out.", zap.Error(ctx.Err()))
		} else {
			a.logger.Error("An error occurred during IDOR detection.", zap.Error(err))
		}
		// Return findings gathered so far along with the error.
		return findings, err
	}

	a.logger.Info("IDOR analysis complete.", zap.Int("potential_findings", len(findings)))
	return findings, nil
}

// validateAndConfigure checks the configuration and sets sensible production defaults.
func (a *IDORAnalyzer) validateAndConfigure(config *Config) error {
	// Validate Sessions
	if config.Session == nil || config.SecondSession == nil {
		return &ErrUnauthenticated{Message: "Both Session and SecondSession must be provided."}
	}
	if !config.Session.IsAuthenticated() {
		return &ErrUnauthenticated{Message: "Primary session is not authenticated."}
	}
	if !config.SecondSession.IsAuthenticated() {
		return &ErrUnauthenticated{Message: "Secondary session is not authenticated."}
	}

	// Set default comparison options if not initialized.
	// We check if the Rules struct within Options is initialized by looking at EntropyThreshold.
	if config.ComparisonOptions.Rules.EntropyThreshold == 0 {
		// Use the default options from the centralized service.
		config.ComparisonOptions = jsoncompare.DefaultOptions()
		a.logger.Info("Using default comparison options from jsoncompare service.")
	}

	// Set default concurrency level
	if config.ConcurrencyLevel <= 0 {
		config.ConcurrencyLevel = runtime.NumCPU() * 5
		if config.ConcurrencyLevel < 10 {
			config.ConcurrencyLevel = 10
		}
		a.logger.Debug("Setting concurrency level.", zap.Int("concurrency", config.ConcurrencyLevel))
	}

	// Set default HTTP client with networking package
	if config.HttpClient == nil {
		a.logger.Debug("Configuring default production HTTP client.")
		// Production-ready HTTP client configuration
		clientConfig := network.NewBrowserClientConfig()
		config.HttpClient = network.NewClient(clientConfig)
	}
	return nil
}
