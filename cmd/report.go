// File: cmd/report.go
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting"
	"github.com/xkilldash9x/scalpel-cli/internal/results"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
)

// storeProvider defines an interface for components that can create a data store
// (schemas.Store). This abstraction is crucial for testing, as it allows for
// the injection of a mock store instead of a live database connection.
type storeProvider interface {
	// Create initializes and returns a schemas.Store, a cleanup function to release
	// resources, and an error if the creation fails.
	Create(ctx context.Context, cfg config.Interface) (schemas.Store, func(), error)
}

// defaultStoreProvider is the concrete implementation of storeProvider used in
// production. It establishes a real connection to the PostgreSQL database.
type defaultStoreProvider struct{}

// NewStoreProvider is a factory function that creates a new defaultStoreProvider.
// It provides a clean way to instantiate the production store provider.
func NewStoreProvider() storeProvider {
	return &defaultStoreProvider{}
}

// Create connects to the PostgreSQL database using the provided configuration,
// initializes the store service, and returns it along with a cleanup function
// to close the database connection pool.
func (p *defaultStoreProvider) Create(ctx context.Context, cfg config.Interface) (schemas.Store, func(), error) {
	logger := observability.GetLogger()
	if cfg.Database().URL == "" {
		return nil, nil, fmt.Errorf("database URL is not configured (SCALPEL_DATABASE_URL)")
	}

	pool, err := pgxpool.New(ctx, cfg.Database().URL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("failed to ping database: %w", err)
	}

	storeService, err := store.New(ctx, pool, logger)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("failed to initialize store service: %w", err)
	}

	cleanup := func() {
		pool.Close()
		logger.Debug("Database connection pool closed (via report cleanup).")
	}
	return storeService, cleanup, nil
}

// newReportCmd creates and configures the `report` command.
func newReportCmd(provider storeProvider) *cobra.Command {
	var scanID string
	var outputPath string
	var format string

	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Process and generate a report for a completed scan",
		Long: `Ingests raw findings from the database for a given scan ID, processes them
(normalization, enrichment, prioritization), and generates a final report.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := observability.GetLogger()

			cfg, err := getConfigFromContext(ctx)
			if err != nil {
				return err
			}

			// Delegate to the testable core logic function.
			return runReport(ctx, logger, cfg, scanID, outputPath, format, provider)
		},
	}

	reportCmd.Flags().StringVar(&scanID, "scan-id", "", "The ID of the scan to generate a report for (required)")
	_ = reportCmd.MarkFlagRequired("scan-id")
	reportCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path. If unset, JSON report is printed to stdout.")
	reportCmd.Flags().StringVarP(&format, "format", "f", "sarif", "Format for the output report (e.g., 'sarif', 'json'). Ignored if printing to stdout.")

	return reportCmd
}

// runReport contains the core, testable logic for generating a report.
func runReport(
	ctx context.Context,
	logger *zap.Logger,
	cfg config.Interface,
	scanID, outputPath, format string,
	provider storeProvider,
) error {
	logger.Info("Starting report generation", zap.String("scan_id", scanID))

	// Initialize Store Service using the injected provider (real or mock).
	storeService, cleanup, err := provider.Create(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	// Ensure cleanup is not nil before deferring (safe for mocks that might not provide a cleanup).
	if cleanup != nil {
		defer cleanup()
	}

	// Process Results
	pipeline := results.NewPipeline(storeService, logger)
	processedResults, err := pipeline.ProcessScanResults(ctx, scanID)
	if err != nil {
		logger.Error("Failed to process results", zap.Error(err), zap.String("scan_id", scanID))
		return fmt.Errorf("failed to process scan results: %w", err)
	}

	finalEnvelope := &schemas.ResultEnvelope{
		ScanID:    scanID,
		Timestamp: time.Now(),
		Findings:  processedResults.Findings,
	}

	// Output Generation
	if outputPath != "" {
		if err := writeReportFile(logger, finalEnvelope, outputPath, format); err != nil {
			return err
		}
	} else {
		if err := printReportToStdout(finalEnvelope); err != nil {
			return err
		}
	}

	return nil
}

// writeReportFile handles writing the report to a file using the reporting module.
func writeReportFile(logger *zap.Logger, envelope *schemas.ResultEnvelope, outputPath, format string) error {
	reporter, err := reporting.New(format, outputPath, Version)
	if err != nil {
		return fmt.Errorf("failed to initialize reporter: %w", err)
	}
	defer func() {
		if err := reporter.Close(); err != nil {
			logger.Warn("Failed to close reporter cleanly.", zap.Error(err))
		}
	}()

	if err := reporter.Write(envelope); err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	logger.Info("Report successfully written to file", zap.String("path", outputPath))
	return nil
}

// printReportToStdout handles printing the report as JSON to standard output.
func printReportToStdout(envelope *schemas.ResultEnvelope) error {
	// Always use pretty-printed JSON for stdout.
	reportJSON, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize report to JSON: %w", err)
	}

	fmt.Fprintln(os.Stdout, string(reportJSON))
	return nil
}
