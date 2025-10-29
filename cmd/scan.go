// File: cmd/scan.go
package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
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

// ComponentFactory defines the interface required by the scan command, matching service.ComponentFactory.
// We redefine the interface here to allow injection of mocks during testing without creating import cycles,
// although we import 'service' to use the concrete Components struct in runScan.
type ComponentFactory interface {
	Create(ctx context.Context, cfg config.Interface, targets []string) (interface{}, error)
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

// runScan contains the core, testable logic for executing a scan.
// It no longer knows how to create components, only how to use them.
func runScan(
	ctx context.Context,
	logger *zap.Logger,
	cfg config.Interface,
	targets []string,
	output, format string,
	factory ComponentFactory,
) error {
	// Initialize all dependencies using the factory.
	rawComponents, err := factory.Create(ctx, cfg, targets)
	if err != nil {
		// If creation fails, the factory handles the shutdown of partially initialized components.
		return fmt.Errorf("failed to initialize scan components: %w", err)
	}
	// Perform a type assertion to get the concrete component struct from the service package.
	components, ok := rawComponents.(*service.Components)
	if !ok {
		// This indicates a programming error (the factory returned the wrong type).
		return fmt.Errorf("component factory returned an invalid type; expected *service.Components but got %T", rawComponents)
	}
	defer components.Shutdown()

	scanID := uuid.New().String()

	// FIX: Replaced the buggy single-target logic with a call to our robust helper function.
	scanTargets, err := normalizeTargets(targets)
	if err != nil {
		return fmt.Errorf("failed to normalize targets: %w", err)
	}

	logger.Info("Starting new scan",
		zap.String("scanID", scanID),
		zap.Strings("targets", scanTargets),
		zap.Int("discovery_depth", cfg.Discovery().MaxDepth),
		zap.Int("engine_concurrency", cfg.Engine().WorkerConcurrency),
		zap.Bool("include_subdomains", cfg.Discovery().IncludeSubdomains),
	)

	// Execute the scan via the orchestrator.
	if err := components.Orchestrator.StartScan(ctx, scanTargets, scanID); err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Warn("Scan aborted gracefully by user signal.", zap.String("scanID", scanID))
			// Return nil as the shutdown was graceful and initiated by the user.
			return nil
		}
		logger.Error("Scan failed during orchestration.", zap.Error(err), zap.String("scanID", scanID))
		return err
	}

	logger.Info("Scan execution completed successfully.", zap.String("scanID", scanID))

	// Generate a report if an output file was specified.
	if output != "" {
		if err := generateReport(ctx, components.Store, scanID, format, output, logger); err != nil {
			return err // Error is already descriptive
		}
	}

	fmt.Printf("\nScan Complete. Scan ID: %s\n", scanID)
	if output == "" {
		fmt.Printf("To generate a report, run: scalpel-cli report --scan-id %s\n", scanID)
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
