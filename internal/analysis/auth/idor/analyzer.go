// analyzer.go
package idor

import (
	"context"
	"log"
	"runtime"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
)

// IDORAnalyzer implements the Analyzer interface and orchestrates the IDOR detection process.
type IDORAnalyzer struct {
	// logger can be used for logging internal state or errors during analysis.
	logger *log.Logger
}

// NewIDORAnalyzer creates and returns a new instance of the IDORAnalyzer.
func NewIDORAnalyzer(logger *log.Logger) Analyzer {
	if logger == nil {
		logger = log.Default()
	}
	return &IDORAnalyzer{
		logger: logger,
	}
}

// AnalyzeTraffic is the main entry point for the analysis logic.
// It orchestrates the detection process, ensuring prerequisites are met before starting the concurrent analysis.
func (a *IDORAnalyzer) AnalyzeTraffic(ctx context.Context, traffic []RequestResponsePair, config Config) ([]Finding, error) {
	a.logger.Println("Starting IDOR analysis...")

	// 1. Validation and Setup
	if len(traffic) == 0 {
		a.logger.Println("No traffic provided to analyze.")
		return nil, nil
	}

	// Validate configuration and set production-ready defaults.
	if err := validateAndConfigure(&config, a.logger); err != nil {
		return nil, err
	}

	// 2. Execute Detection Logic
	// The Detect function handles concurrency and robust comparison.
	findings, err := Detect(ctx, traffic, config, a.logger)
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
func validateAndConfigure(config *Config, logger *log.Logger) error {
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

	// Set default comparison rules if empty (checking EntropyThreshold as a proxy for initialization)
	if config.ComparisonRules.EntropyThreshold == 0 && len(config.ComparisonRules.KeyPatterns) == 0 {
		config.ComparisonRules = DefaultHeuristicRules()
		logger.Println("Using default heuristic comparison rules.")
	}

	// Set default concurrency level
	if config.ConcurrencyLevel <= 0 {
		// Default suitable for I/O bound work (network requests).
		config.ConcurrencyLevel = runtime.NumCPU() * 5
		if config.ConcurrencyLevel < 10 {
			config.ConcurrencyLevel = 10
		}
		logger.Printf("Setting concurrency level to %d.", config.ConcurrencyLevel)
	}

	// Set default HTTP client with networking package
	if config.HttpClient == nil {
		logger.Println("Configuring default production HTTP client.")
		// Production-ready HTTP client configuration
		clientConfig := network.NewBrowserClientConfig()
		config.HttpClient = network.NewClient(clientConfig)
	}
	return nil
}
