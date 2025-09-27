// File: cmd/scan.go
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/discovery"
	"github.com/xkilldash9x/scalpel-cli/internal/engine"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/orchestrator"
	"github.com/xkilldash9x/scalpel-cli/internal/reporting"
	"github.com/xkilldash9x/scalpel-cli/internal/results"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
)

// newScanCmd creates and configures the `scan` command and its flags.
func newScanCmd() *cobra.Command {
	var scanCfg config.ScanConfig

	scanCmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Starts a new security scan against the specified targets",
		Long: `Initializes and runs the full scalpel-cli scanning pipeline.
This includes discovery, task execution, and analysis against one or more root targets.
Targets can be specified as command-line arguments.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanCfg.Targets = args
			scanID := uuid.New().String()
			logger := observability.GetLogger()
			cfg := config.Get()

			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return fmt.Errorf("failed to bind command flags: %w", err)
			}
			if err := viper.Unmarshal(cfg); err != nil {
				return fmt.Errorf("failed to re-unmarshal config with flag overrides: %w", err)
			}

			logger.Info("Starting new scan", zap.String("scanID", scanID), zap.Strings("targets", scanCfg.Targets))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				sig := <-sigChan
				logger.Warn("Received termination signal, shutting down gracefully...", zap.String("signal", sig.String()))
				cancel()
				time.Sleep(2 * time.Second)
				os.Exit(1)
			}()

			logger.Debug("Initializing components...")

			dbPool, err := pgxpool.New(ctx, cfg.Database.URL)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %w", err)
			}
			defer dbPool.Close()

			dbStore, err := store.New(ctx, dbPool, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize database store: %w", err)
			}

			browserManager, err := browser.NewManager(ctx, logger, cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize browser manager: %w", err)
			}
			defer browserManager.Shutdown(ctx)

			kg, err := agent.NewGraphStoreFromConfig(ctx, cfg.Agent.KnowledgeGraph, dbPool, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize knowledge graph store: %w", err)
			}

			taskEngine, err := engine.New(cfg, logger, dbStore, browserManager, kg)
			if err != nil {
				return fmt.Errorf("failed to initialize task engine: %w", err)
			}

			scopeManager, err := discovery.NewBasicScopeManager(args[0], true)
			if err != nil {
				return fmt.Errorf("failed to initialize scope manager: %w", err)
			}

			httpClient := network.NewClient(nil)
			httpAdapter := discovery.NewHTTPClientAdapter(httpClient)

			discoveryCfg := discovery.Config{
				MaxDepth:           cfg.Discovery.MaxDepth,
				Concurrency:        cfg.Discovery.Concurrency,
				Timeout:            cfg.Discovery.Timeout,
				PassiveEnabled:     cfg.Discovery.PassiveEnabled,
				CrtShRateLimit:     cfg.Discovery.CrtShRateLimit,
				CacheDir:           cfg.Discovery.CacheDir,
				PassiveConcurrency: cfg.Discovery.PassiveConcurrency,
			}

			passiveRunner := discovery.NewPassiveRunner(discoveryCfg, httpAdapter, scopeManager, logger)
			discoveryEngine := discovery.NewEngine(discoveryCfg, scopeManager, kg, browserManager, passiveRunner, logger)

			logger.Debug("Injecting dependencies into orchestrator...")

			orch, err := orchestrator.New(cfg, logger, discoveryEngine, taskEngine)
			if err != nil {
				return fmt.Errorf("failed to create orchestrator: %w", err)
			}

			if err := orch.StartScan(ctx, scanCfg.Targets, scanID); err != nil {
				logger.Error("Scan failed during orchestration", zap.Error(err), zap.String("scanID", scanID))
				return err
			}

			logger.Info("Scan discovery and task execution completed successfully", zap.String("scanID", scanID))

			if scanCfg.Output != "" {
				logger.Info("Generating scan report...", zap.String("format", scanCfg.Format), zap.String("output_path", scanCfg.Output))
				reporter, err := reporting.New(scanCfg.Format, scanCfg.Output, logger, Version)
				if err != nil {
					return fmt.Errorf("failed to initialize reporter: %w", err)
				}

				pipeline := results.NewPipeline(dbStore, logger)
				results, err := pipeline.ProcessScanResults(ctx, scanID)
				if err != nil {
					return fmt.Errorf("failed to process scan results for reporting: %w", err)
				}

				finalEnvelope := &schemas.ResultEnvelope{
					ScanID:   scanID,
					Findings: results.Findings,
				}

				if err := reporter.Write(finalEnvelope); err != nil {
					_ = reporter.Close()
					return fmt.Errorf("failed to write report: %w", err)
				}
				if err := reporter.Close(); err != nil {
					return fmt.Errorf("failed to finalize and close report: %w", err)
				}
				logger.Info("Report generated successfully.", zap.String("path", scanCfg.Output))
			}

			fmt.Printf("\nScan Complete. Scan ID: %s\n", scanID)
			if scanCfg.Output == "" {
				fmt.Printf("To generate a report, run: scalpel-cli report --scan-id %s\n", scanID)
			}

			return nil
		},
	}

	scanCmd.Flags().StringVarP(&scanCfg.Output, "output", "o", "", "Output file path for the report. If unset, no report is generated.")
	scanCmd.Flags().StringVarP(&scanCfg.Format, "format", "f", "sarif", "Format for the output report (e.g., 'sarif', 'json').")
	scanCmd.Flags().IntVar(&scanCfg.Depth, "depth", 0, "Maximum crawl depth. (0 uses config default)")
	scanCmd.Flags().IntVar(&scanCfg.Concurrency, "concurrency", 0, "Number of concurrent browser instances. (0 uses config default)")

	return scanCmd
}