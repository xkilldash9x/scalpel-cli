// cmd/scan.go
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
	"github.comcom/xkilldash9x/scalpel-cli/pkg/orchestrator"
	"github.com/xkilldash9x/scalpel-cli/pkg/reporting"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
	"github.com/xkilldash9x/scalpel-cli/pkg/store"
)

var scanCmd = &cobra.Command{
	Use:   "scan [target...]",
	Short: "Run a security scan against one or more targets",
	Long:  `The scan command is the main entrypoint for running Scalpel's analysis engines. It orchestrates discovery, analysis, and persistence, then generates a final report.`,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := observability.GetLogger()
		cfg := config.Get()

		// Bind flags from viper to the scan config struct
		cfg.Scan.Targets = args
		cfg.Scan.Output = viper.GetString("scan.output")
		cfg.Scan.Format = viper.GetString("scan.format")
		cfg.Scan.Concurrency = viper.GetInt("scan.concurrency")
		cfg.Scan.Depth = viper.GetInt("scan.depth")
		cfg.Scan.Scope = viper.GetString("scan.scope")

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		orch, err := orchestrator.New(cfg, logger)
		if err != nil {
			logger.Fatal("Failed to initialize orchestrator", zap.Error(err))
		}

		logger.Info("Starting scan orchestrator", zap.Strings("targets", args))
		scanID, err := orch.StartScan(ctx, args)
		if err != nil {
			logger.Error("Scan execution failed", zap.Error(err))
			// Still attempt to report any partial findings
		} else {
			logger.Info("Scan completed successfully.")
		}

		// --- Reporting Phase ---
		logger.Info("Starting reporting phase", zap.String("scanID", scanID))
		if err := generateReport(scanID, cfg); err != nil {
			logger.Error("Failed to generate report", zap.Error(err))
			return err
		}

		return nil
	},
}

func generateReport(scanID string, cfg *config.Config) error {
	logger := observability.GetLogger()
	ctx := context.Background()

	// Initialize a new store connection for reporting
	storeService, err := store.New(ctx, cfg.Postgres.URL, logger)
	if err != nil {
		return fmt.Errorf("failed to connect to store for reporting: %w", err)
	}
	defer storeService.Close()

	// Fetch all findings for the completed scan
	findings, err := storeService.GetFindingsByScanID(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to retrieve findings for scan %s: %w", scanID, err)
	}

	if len(findings) == 0 {
		logger.Info("No findings were recorded for this scan.")
		return nil
	}

	// Initialize the reporter based on CLI flags
	reporter, err := reporting.New(cfg.Scan.Format, cfg.Scan.Output)
	if err != nil {
		return fmt.Errorf("failed to initialize reporter: %w", err)
	}
	defer reporter.Close()

	// Group findings by TaskID to reconstruct ResultEnvelopes for the reporter
	findingsByTask := make(map[string][]schemas.Finding)
	for _, f := range findings {
		findingsByTask[f.TaskID] = append(findingsByTask[f.TaskID], f)
	}

	logger.Info("Writing findings to report", zap.Int("total_findings", len(findings)), zap.String("format", cfg.Scan.Format))

	// Write each "task's worth" of findings to the reporter
	for taskID, taskFindings := range findingsByTask {
		envelope := &schemas.ResultEnvelope{
			ScanID:   scanID,
			TaskID:   taskID,
			Findings: taskFindings,
		}
		if err := reporter.Write(envelope); err != nil {
			// Log the error but continue trying to write other results
			logger.Error("Failed to write result envelope to report", zap.Error(err), zap.String("task_id", taskID))
		}
	}

	logger.Info("Report generation complete.", zap.String("output", cfg.Scan.Output))
	return nil
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("output", "o", "stdout", "File to write report to (or stdout)")
	scanCmd.Flags().StringP("format", "f", "sarif", "Output format (sarif, json, text)")
	scanCmd.Flags().IntP("concurrency", "C", 10, "Number of concurrent analyzers")
	scanCmd.Flags().IntP("depth", "d", 3, "Maximum depth for crawling")
	scanCmd.Flags().String("scope", "subdomain", "Scope of the scan (root, subdomain, strict)")

	viper.BindPFlag("scan.output", scanCmd.Flags().Lookup("output"))
	viper.BindPFlag("scan.format", scanCmd.Flags().Lookup("format"))
	viper.BindPFlag("scan.concurrency", scanCmd.Flags().Lookup("concurrency"))
	viper.BindPFlag("scan.depth", scanCmd.Flags().Lookup("depth"))
	viper.BindPFlag("scan.scope", scanCmd.Flags().Lookup("scope"))
}
