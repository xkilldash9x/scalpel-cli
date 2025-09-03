// -- cmd/scalpel-cli/report.go --
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
	"github.com/xkilldash9x/scalpel-cli/pkg/results"
	"github.com/xkilldash9x/scalpel-cli/pkg/store"
)

func newReportCmd() *cobra.Command {
	var scanID string

	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Process and generate a report for a completed scan",
		Long:  `Ingests raw findings from the database for a given scan ID, then runs them through a normalization, enrichment, and prioritization pipeline to generate a final JSON report.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if scanID == "" {
				return fmt.Errorf("a scan-id must be provided")
			}

			ctx := cmd.Context()
			logger := observability.GetLogger()

			cfg, err := config.Load(logger, "./config.yaml")
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			storeService, err := store.New(ctx, cfg.Postgres.URL, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize store service: %w", err)
			}
			defer storeService.Close()

			pipeline := results.NewPipeline(storeService, logger)
			report, err := pipeline.ProcessScanResults(ctx, scanID)
			if err != nil {
				logger.Error("Failed to process results", zap.Error(err), zap.String("scan_id", scanID))
				return err
			}

			reportJSON, err := report.ToJSON()
			if err != nil {
				return fmt.Errorf("failed to serialize report to JSON: %w", err)
			}

			// Print the final report to standard output.
			fmt.Println(reportJSON)

			return nil
		},
	}

	reportCmd.Flags().StringVar(&scanID, "scan-id", "", "The ID of the scan to generate a report for (required)")
	_ = reportCmd.MarkFlagRequired("scan-id")

	return reportCmd
}
