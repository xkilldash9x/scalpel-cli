// File: internal/analysis/auth/idor/analyzer.go
package idor

import (
	"context"
	"fmt"
	"log"
	"runtime"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// IDORAnalyzer is the main orchestrator for the Insecure Direct Object Reference
// (IDOR) detection process. It implements the `Analyzer` interface.
type IDORAnalyzer struct {
	logger   *log.Logger                // Standard logger for compatibility.
	comparer jsoncompare.JSONComparison // The injected service for semantic JSON comparison.
}

// NewIDORAnalyzer creates a new instance of the IDORAnalyzer.
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

// AnalyzeTraffic is the primary entry point for the IDOR analysis.
func (a *IDORAnalyzer) AnalyzeTraffic(ctx context.Context, traffic []RequestResponsePair, config Config) ([]Finding, error) {
	a.logger.Println("Starting IDOR analysis...")

	// 1. Validation and Setup
	if len(traffic) == 0 {
		a.logger.Println("No traffic provided to analyze.")
		return nil, nil
	}

	// Validate configuration and set production-ready defaults.
	// This dynamically modifies the config based on available sessions.
	if err := a.validateAndConfigure(&config); err != nil {
		return nil, err
	}

	// Check if any strategy remains enabled after validation
	if config.SkipHorizontal && config.SkipManipulation && config.SkipUnauthenticated {
		a.logger.Println("All IDOR analysis strategies are disabled or cannot run. Exiting.")
		return nil, nil
	}

	// 2. Execute Detection Logic
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

// validateAndConfigure checks the configuration, sets defaults, and adjusts strategies based on available sessions.
func (a *IDORAnalyzer) validateAndConfigure(config *Config) error {
	// Validate Sessions for Authenticated Strategies
	requiresPrimarySession := !config.SkipManipulation
	requiresSecondSession := !config.SkipHorizontal

	// Check Primary Session (User A)
	if requiresPrimarySession {
		if config.Session == nil || !config.Session.IsAuthenticated() {
			a.logger.Println("Warning: Primary session (User A) missing or unauthenticated. Disabling Manipulation checks.")
			config.SkipManipulation = true
		}
	}

	// Check Secondary Session (User B)
	if requiresSecondSession {
		if config.Session == nil || !config.Session.IsAuthenticated() {
			// Cannot run Horizontal if User A is missing (need User A's traffic context)
			a.logger.Println("Warning: Primary session (User A) missing or unauthenticated. Disabling Horizontal checks.")
			config.SkipHorizontal = true
		} else if config.SecondSession == nil || !config.SecondSession.IsAuthenticated() {
			// If SecondSession is missing, we can still run Manipulation and Unauthenticated.
			a.logger.Println("Warning: Secondary session (User B) missing or unauthenticated. Disabling Horizontal checks.")
			config.SkipHorizontal = true
		}
	}

	// Handle cases where no authenticated sessions are available.
	isAuthenticatedAvailable := (config.Session != nil && config.Session.IsAuthenticated())
	if !isAuthenticatedAvailable {
		if !config.SkipUnauthenticated {
			a.logger.Println("No valid authenticated sessions provided. Proceeding with Unauthenticated checks only.")
			// Ensure authenticated strategies are marked as skipped.
			config.SkipHorizontal = true
			config.SkipManipulation = true
		} else {
			// Error if no sessions are available AND unauthenticated checks are disabled.
			return fmt.Errorf("no valid sessions provided and Unauthenticated checks are disabled; nothing to analyze")
		}
	}

	// Set default comparison options if not initialized.
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
