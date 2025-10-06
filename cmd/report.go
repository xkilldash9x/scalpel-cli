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

// newReportCmd creates and configures the `report` command.
func newReportCmd() *cobra.Command {
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
			cfg := config.Get()

			logger.Info("Starting report generation", zap.String("scan_id", scanID))

			// Initialize Database Connection
			pool, err := connectToDatabase(ctx, cfg.Database.URL)
			if err != nil {
				return err
			}
			defer pool.Close()

			// Initialize Store Service
			storeService, err := store.New(ctx, pool, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize store service: %w", err)
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
		},
	}

	reportCmd.Flags().StringVar(&scanID, "scan-id", "", "The ID of the scan to generate a report for (required)")
	_ = reportCmd.MarkFlagRequired("scan-id")
	reportCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path. If unset, JSON report is printed to stdout.")
	reportCmd.Flags().StringVarP(&format, "format", "f", "sarif", "Format for the output report (e.g., 'sarif', 'json'). Ignored if printing to stdout.")

	return reportCmd
}

// connectToDatabase establishes a connection pool.
func connectToDatabase(ctx context.Context, dbURL string) (*pgxpool.Pool, error) {
	if dbURL == "" {
		return nil, fmt.Errorf("database URL is not configured (SCALPEL_DATABASE_URL)")
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return pool, nil
}

// writeReportFile handles writing the report to a file using the reporting module.
func writeReportFile(logger *zap.Logger, envelope *schemas.ResultEnvelope, outputPath, format string) error {
	reporter, err := reporting.New(format, outputPath, logger, Version)
	if err != nil {
		return fmt.Errorf("failed to initialize reporter: %w", err)
	}
	defer reporter.Close()

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