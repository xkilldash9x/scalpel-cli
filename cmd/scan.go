// File: cmd/scan.go
package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting"
	"github.com/xkilldash9x/scalpel-cli/internal/results"
	"github.com/xkilldash9x/scalpel-cli/internal/service"
)

// ComponentFactory defines an interface for creating the full suite of services
// required for a scan. This abstraction allows for dependency injection, making
// the `scan` command testable by allowing mocks to be provided instead of live
// components.
type ComponentFactory interface {
	// Create initializes and returns all necessary components for a scan, such as
	// the orchestrator, knowledge graph, and various clients. It returns an
	// interface{} that is expected to be of type *service.Components.
	Create(ctx context.Context, cfg config.Interface, targets []string, logger *zap.Logger) (interface{}, error)
}

// newScanCmd creates and configures the `scan` command.
// It is now decoupled from the component initialization logic.
func newScanCmd(factory ComponentFactory) *cobra.Command {
	scanCmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Starts a new security scan against the specified targets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := observability.GetLogger()

			cfg, err := getConfigFromContext(ctx)
			if err != nil {
				return err // Error is already descriptive
			}

			// Apply flag-based overrides to the configuration.
			// This logic is now cleanly separated and easy to test.
			applyScanFlagOverrides(cmd, cfg)

			output, _ := cmd.Flags().GetString("output")
			format, _ := cmd.Flags().GetString("format")
			targets := args

			// The core logic is delegated to a testable function that accepts
			// the factory as a dependency.
			return runScan(ctx, logger, cfg, targets, output, format, factory)
		},
	}

	scanCmd.Flags().StringP("output", "o", "", "Output file path for the report. If unset, no report is generated.")
	scanCmd.Flags().StringP("format", "f", "sarif", "Format for the output report (e.g., 'sarif', 'json').")
	scanCmd.Flags().IntP("depth", "d", 0, "Maximum crawl depth. (Overrides config/env)")
	scanCmd.Flags().IntP("concurrency", "j", 0, "Number of concurrent engine workers. (Overrides config/env)")
	scanCmd.Flags().String("scope", "strict", "Scan scope strategy ('strict' or 'subdomain'). (Overrides config/env)")

	return scanCmd
}

// applyScanFlagOverrides centralizes the logic for updating the config based on CLI flags.
func applyScanFlagOverrides(cmd *cobra.Command, cfg config.Interface) {
	logger := observability.GetLogger()

	if cmd.Flags().Changed("depth") {
		depth, _ := cmd.Flags().GetInt("depth")
		cfg.SetDiscoveryMaxDepth(depth)
		logger.Debug("Applied --depth flag override.", zap.Int("value", depth))
	}
	if cmd.Flags().Changed("concurrency") {
		concurrency, _ := cmd.Flags().GetInt("concurrency")
		cfg.SetEngineWorkerConcurrency(concurrency)
		logger.Debug("Applied --concurrency flag override.", zap.Int("value", concurrency))
	}
	if cmd.Flags().Changed("scope") {
		scope, _ := cmd.Flags().GetString("scope")
		switch strings.ToLower(scope) {
		case "subdomain":
			cfg.SetDiscoveryIncludeSubdomains(true)
			logger.Debug("Applied --scope flag override.", zap.String("value", "subdomain"))
		case "strict":
			cfg.SetDiscoveryIncludeSubdomains(false)
			logger.Debug("Applied --scope flag override.", zap.String("value", "strict"))
		default:
			logger.Warn("Invalid --scope value provided, defaulting to 'strict'.", zap.String("provided_scope", scope))
			cfg.SetDiscoveryIncludeSubdomains(false)
		}
	}
}

// FIX: This new helper function correctly normalizes all target URLs.
// It loops through every target, adds a default scheme if missing, and validates the result.
func normalizeTargets(targets []string) ([]string, error) {
	normalized := make([]string, 0, len(targets))
	for _, target := range targets {
		if strings.TrimSpace(target) == "" {
			continue
		}

		// Trim and then check for a scheme
		t := strings.TrimSpace(target)
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			t = "https://" + t
		}

		// Parse the URL to validate its structure.
		u, err := url.Parse(t)
		if err != nil {
			return nil, fmt.Errorf("invalid target URL '%s': %w", target, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("malformed target URL after normalization: '%s'", t)
		}

		normalized = append(normalized, u.String())
	}
	return normalized, nil
}

// runScan orchestrates the entire scan lifecycle, including component initialization,
// execution, and graceful shutdown. It sets up a signal handler to intercept
// interrupt signals (like Ctrl+C), allowing the application to terminate cleanly.
func runScan(
	ctx context.Context,
	logger *zap.Logger,
	cfg config.Interface,
	targets []string,
	output, format string,
	factory ComponentFactory,
) error {
	// --- Graceful Shutdown Setup ---
	// Create a context that can be canceled manually. This will be the main context for the scan.
	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan() // Ensure cancel is called to free resources.

	// Set up a channel to listen for OS signals (SIGINT, SIGTERM).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Launch a goroutine to handle signal notifications.
	go func() {
		// Block until a signal is received.
		sig := <-sigChan
		logger.Warn("Received shutdown signal, initiating graceful shutdown.", zap.String("signal", sig.String()))

		// Trigger the cancellation of the scan context.
		cancelScan()
	}()

	// --- Target Validation ---
	scanTargets, err := normalizeTargets(targets)
	if err != nil {
		return fmt.Errorf("failed to normalize targets: %w", err)
	}

	// --- Component Initialization ---
	// Initialize all dependencies using the factory, passing the cancelable scan context.
	rawComponents, err := factory.Create(scanCtx, cfg, scanTargets, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize scan components: %w", err)
	}
	components, ok := rawComponents.(*service.Components)
	if !ok {
		return fmt.Errorf("component factory returned an invalid type; expected *service.Components but got %T", rawComponents)
	}
	// Use a deferred function to ensure Shutdown is always called, even on panic.
	defer func() {
		logger.Info("Starting component shutdown...")
		// The Shutdown method now handles its own timeout.
		components.Shutdown()
		logger.Info("Component shutdown complete.")
	}()

	// --- Scan Execution ---
	scanID := uuid.New().String()

	logger.Info("Starting new scan",
		zap.String("scanID", scanID),
		zap.Strings("targets", scanTargets),
		zap.Int("discovery_depth", cfg.Discovery().MaxDepth),
		zap.Int("engine_concurrency", cfg.Engine().WorkerConcurrency),
		zap.Bool("include_subdomains", cfg.Discovery().IncludeSubdomains),
	)

	if err := components.Orchestrator.StartScan(scanCtx, scanTargets, scanID); err != nil {
		// If the error is due to context cancellation, it's a graceful shutdown.
		if errors.Is(err, context.Canceled) {
			logger.Warn("Scan aborted by user signal.", zap.String("scanID", scanID))
			return nil // Return nil for a clean exit.
		}
		// Otherwise, it's an unexpected error during the scan.
		logger.Error("Scan failed during orchestration.", zap.Error(err), zap.String("scanID", scanID))
		return err
	}

	// --- Report Generation ---
	// Check if the scan was canceled before generating the report.
	if scanCtx.Err() == context.Canceled {
		logger.Info("Skipping report generation due to scan cancellation.", zap.String("scanID", scanID))
	} else {
		logger.Info("Scan execution completed successfully.", zap.String("scanID", scanID))
		if output != "" {
			if err := generateReport(ctx, components.Store, scanID, format, output, logger); err != nil {
				return err
			}
		}
		fmt.Printf("\nScan Complete. Scan ID: %s\n", scanID)
		if output == "" {
			fmt.Printf("To generate a report, run: scalpel-cli report --scan-id %s\n", scanID)
		}
	}

	return nil
}

// startFindingsConsumer has been moved to internal/service/initializers.go
// and significantly improved with batching and robust shutdown handling.

// generateReport handles result processing and report writing.
func generateReport(_ context.Context, dbStore schemas.Store, scanID, format, outputPath string, logger *zap.Logger) error {
	logger.Info("Generating scan report...", zap.String("format", format), zap.String("output_path", outputPath))

	// Use a background context for report generation to ensure it completes
	// even if the main scan context was canceled (e.g., by Ctrl+C after the scan finished).
	reportCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	reporter, err := reporting.New(format, outputPath, logger, Version)
	if err != nil {
		return fmt.Errorf("failed to initialize reporter: %w", err)
	}
	defer func() {
		if closeErr := reporter.Close(); closeErr != nil {
			logger.Error("Failed to close reporter.", zap.Error(closeErr))
		}
	}()

	pipeline := results.NewPipeline(dbStore, logger)
	processedResults, err := pipeline.ProcessScanResults(reportCtx, scanID)
	if err != nil {
		return fmt.Errorf("failed to process scan results: %w", err)
	}

	finalEnvelope := &schemas.ResultEnvelope{
		ScanID:    scanID,
		Timestamp: time.Now(),
		Findings:  processedResults.Findings,
	}

	if err := reporter.Write(finalEnvelope); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	logger.Info("Report generated successfully.", zap.String("path", outputPath))
	return nil
}
