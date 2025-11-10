// File: internal/analysis/auth/idor/analyzer.go
package idor

import (
	"context"
	"log"
	"runtime"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// IDORAnalyzer is the main orchestrator for the Insecure Direct Object Reference
// (IDOR) detection process. It implements the `Analyzer` interface and uses a
// JSON comparison service to semantically compare HTTP responses.
type IDORAnalyzer struct {
	logger   *log.Logger // Standard logger for compatibility.
	comparer jsoncompare.JSONComparison // The injected service for semantic JSON comparison.
}

// NewIDORAnalyzer creates a new instance of the IDORAnalyzer. It requires a
// logger and an implementation of the `jsoncompare.JSONComparison` interface.
// If the comparer is nil, it initializes a default instance with a warning.
func NewIDORAnalyzer(logger *log.Logger, comparer jsoncompare.JSONComparison) Analyzer {
	if logger == nil {
		logger = log.Default()
	}
	// Ensure the comparer is provided.
	if comparer == nil {
		// If not injected (e.g., in older tests), initialize a default service instance and log a warning.
		observability.GetLogger().Warn("JSONComparer not injected into IDORAnalyzer, initializing default service.")
		comparer = jsoncompare.NewService()
	}

	return &IDORAnalyzer{
		logger:   logger,
		comparer: comparer,
	}
}

// AnalyzeTraffic is the primary entry point for the IDOR analysis. It takes a
// slice of HTTP traffic, validates the configuration, sets production-ready
// defaults, and then invokes the core detection logic.
func (a *IDORAnalyzer) AnalyzeTraffic(ctx context.Context, traffic []RequestResponsePair, config Config) ([]Finding, error) {
	a.logger.Println("Starting IDOR analysis...")

	// 1. Validation and Setup
	if len(traffic) == 0 {
		a.logger.Println("No traffic provided to analyze.")
		return nil, nil
	}

	// Validate configuration and set production-ready defaults.
	if err := a.validateAndConfigure(&config); err != nil {
		return nil, err
	}

	// 2. Execute Detection Logic
	// Pass the injected comparer service to the detection logic.
	findings, err := Detect(ctx, traffic, config, a.logger, a.comparer)
	if err != nil {
		// Check if the error is due to context cancellation.
		if ctx.Err() != nil {
			a.logger.Printf("IDOR analysis cancelled or timed out: %v", ctx.Err())
		} else {
			a.logger.Printf("An error occurred during IDOR detection: %v", err)
		}
		// Return findings gathered so far along with the error.
		return findings, err
	}

	a.logger.Printf("IDOR analysis complete. Found %d potential findings.", len(findings))
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
		a.logger.Println("Using default comparison options from jsoncompare service.")
	}

	// Set default concurrency level
	if config.ConcurrencyLevel <= 0 {
		config.ConcurrencyLevel = runtime.NumCPU() * 5
		if config.ConcurrencyLevel < 10 {
			config.ConcurrencyLevel = 10
		}
		a.logger.Printf("Setting concurrency level to %d.", config.ConcurrencyLevel)
	}

	// Set default HTTP client with networking package
	if config.HttpClient == nil {
		a.logger.Println("Configuring default production HTTP client.")
		// Production-ready HTTP client configuration
		clientConfig := network.NewBrowserClientConfig()
		config.HttpClient = network.NewClient(clientConfig)
	}
	return nil
}
