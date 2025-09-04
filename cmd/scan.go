package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/agent"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/discovery"
	"github.com/xkilldash9x/scalpel-cli/pkg/engine"
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
	"github.com/xkilldash9x/scalpel-cli/pkg/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/pkg/llmclient"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
	"github.com/xkilldash9x/scalpel-cli/pkg/orchestrator"
	"github.com/xkilldash9x/scalpel-cli/pkg/reporting"
	"github.com/xkilldash9x/scalpel-cli/pkg/store"
)

func newScanCmd() *cobra.Command {
	var scanCfg config.ScanConfig

	scanCmd := &cobra.Command{
		Use:   "scan [target...]",
		Short: "Run a full scan against one or more targets",
		Long: `
The scan command orchestrates the entire lifecycle of a security assessment.
It initializes all necessary components—including the browser manager, task engine,
and knowledge graph—then proceeds with discovery and analysis phases before
generating a final report.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanCfg.Targets = args
			scanID := uuid.New().String()
			logger := observability.GetLogger().With(zap.String("scan_id", scanID))

			// Use viper to get the full config struct.
			var cfg config.Config
			if err := viper.Unmarshal(&cfg); err != nil {
				return fmt.Errorf("failed to unmarshal config: %w", err)
			}
			cfg.Scan = scanCfg // Overwrite scan-specific part with flag values.

			// Setup context for graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			shutdownChan := make(chan os.Signal, 1)
			signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				sig := <-shutdownChan
				logger.Warn("Shutdown signal received", zap.String("signal", sig.String()))
				cancel()
			}()

			// -- Composition Root: Instantiate all concrete services --
			storeService, err := store.New(ctx, cfg.Postgres.URL, logger)
			if err != nil {
				return fmt.Errorf("failed to initialize store service: %w", err)
			}
			defer storeService.Close()

			browserManager, err := browser.NewManager(ctx, logger, &cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize browser manager: %w", err)
			}
			defer browserManager.Shutdown(ctx)

			kg, err := knowledgegraph.NewPostgresKG(ctx, storeService.GetPool())
			if err != nil {
				return fmt.Errorf("failed to initialize knowledge graph: %w", err)
			}

			// Instantiate LLM client for the agent
			llmClient, err := llmclient.NewClient(cfg.Agent, logger)
			if err != nil {
				return fmt.Errorf("failed to create LLM client: %w", err)
			}

			// Instantiate engines, injecting dependencies as interfaces
			taskEngine, err := engine.New(&cfg, logger, storeService, browserManager, kg)
			if err != nil {
				return fmt.Errorf("failed to initialize task engine: %w", err)
			}

			scope, err := discovery.NewBasicScopeManager(scanCfg.Targets[0], true)
			if err != nil {
				return fmt.Errorf("failed to initialize scope manager: %w", err)
			}
			
			// This is a temporary measure for the refactor.
			// The http client should be a shared global service.
			httpClient := &http.Client{Timeout: 10 * time.Second}
			passiveRunner := discovery.NewPassiveRunner(cfg.Discovery, httpClient, scope, logger)

			discoveryEngine := discovery.NewEngine(cfg.Discovery, scope, kg, nil, browserManager, passiveRunner, logger)

			// Create the orchestrator with its dependencies
			orch, err := orchestrator.New(&cfg, logger, discoveryEngine, taskEngine)
			if err != nil {
				return fmt.Errorf("failed to create orchestrator: %w", err)
			}

			// -- Execute Scan --
			if err := orch.StartScan(ctx, scanCfg.Targets, scanID); err != nil {
				logger.Error("Scan orchestration failed", zap.Error(err))
			}

			// -- Reporting --
			reporter, err := reporting.New(scanCfg.Format, scanCfg.Output)
			if err != nil {
				return fmt.Errorf("failed to create reporter: %w", err)
			}
			defer reporter.Close()

			pipeline := results.NewPipeline(storeService, logger)
			report, err := pipeline.ProcessScanResults(ctx, scanID)
			if err != nil {
				return fmt.Errorf("failed to process scan results: %w", err)
			}
			if err := report.WriteJSON(reporter); err != nil {
				return fmt.Errorf("failed to write report: %w", err)
			}

			logger.Info("Scan complete and report generated.", zap.String("output", scanCfg.Output))
			return nil
		},
	}

	// Add flags for scan-specific configuration
	scanCmd.Flags().StringVarP(&scanCfg.Output, "output", "o", "stdout", "Output file for the report (e.g., report.json)")
	scanCmd.Flags().StringVarP(&scanCfg.Format, "format", "f", "json", "Output format (json, sarif, text)")
	scanCmd.Flags().IntVarP(&scanCfg.Depth, "depth", "d", 3, "Maximum depth for the crawler")
	scanCmd.Flags().StringVar(&scanCfg.Scope, "scope", "subdomain", "Scan scope (strict, root, subdomain)")

	return scanCmd
}
