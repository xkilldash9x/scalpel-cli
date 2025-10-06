// File: cmd/scan.go
package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	// Import necessary internal packages
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

// newScanCmd creates and configures the `scan` command.
func newScanCmd() *cobra.Command {
	// Local struct to capture output flags specifically.
	var outputFlags struct {
		Output string
		Format string
	}

	scanCmd := &cobra.Command{
		Use:   "scan [targets...]",
		Short: "Starts a new security scan against the specified targets",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use the context passed from main.go (signal-aware).
			ctx := cmd.Context()
			logger := observability.GetLogger()

			// 1. Configuration Finalization
			// Bind flags to viper. This allows flags defined below to override config file/env vars.
			if err := viper.BindPFlags(cmd.Flags()); err != nil {
				return fmt.Errorf("failed to bind command flags: %w", err)
			}

			cfg := config.Get()

			// Re-unmarshal the config to apply any flag overrides (e.g., --depth, --concurrency).
			if err := viper.Unmarshal(cfg); err != nil {
				return fmt.Errorf("failed to re-unmarshal config with flag overrides: %w", err)
			}

			scanID := uuid.New().String()
			targets := args

			logger.Info("Starting new scan",
				zap.String("scanID", scanID),
				zap.Strings("targets", targets),
				// Logging the effective configuration values
				zap.Int("discovery_depth", cfg.Discovery.MaxDepth),
				zap.Int("engine_concurrency", cfg.Engine.WorkerConcurrency),
			)

			// 2. Initialize Core Components
			components, err := initializeScanComponents(ctx, cfg, targets, logger)
			if err != nil {
				// Ensure components initialized so far are closed before returning
				if components != nil {
					components.Shutdown(ctx)
				}
				return fmt.Errorf("failed to initialize scan components: %w", err)
			}
			// Ensure components are shut down when the function returns.
			defer components.Shutdown(ctx)

			// 3. Execute Scan Orchestration
			if err := components.Orchestrator.StartScan(ctx, targets, scanID); err != nil {
				// Check if the error was due to context cancellation (graceful shutdown)
				if errors.Is(err, context.Canceled) {
					logger.Warn("Scan aborted gracefully", zap.String("scanID", scanID))
					return fmt.Errorf("scan aborted by user signal")
				}
				logger.Error("Scan failed during orchestration", zap.Error(err), zap.String("scanID", scanID))
				return err
			}

			logger.Info("Scan execution completed successfully", zap.String("scanID", scanID))

			// 4. Reporting
			if outputFlags.Output != "" {
				if err := generateReport(ctx, components.Store, scanID, outputFlags.Format, outputFlags.Output, logger); err != nil {
					return err
				}
			}

			// 5. Final Output
			fmt.Printf("\nScan Complete. Scan ID: %s\n", scanID)
			if outputFlags.Output == "" {
				fmt.Printf("To generate a report, run: scalpel-cli report --scan-id %s\n", scanID)
			}

			return nil
		},
	}

	// Reporting flags
	scanCmd.Flags().StringVarP(&outputFlags.Output, "output", "o", "", "Output file path for the report. If unset, no report is generated.")
	scanCmd.Flags().StringVarP(&outputFlags.Format, "format", "f", "sarif", "Format for the output report (e.g., 'sarif', 'json').")

	// Scan configuration override flags. We bind these directly to Viper config keys.
	// Setting the default to 0 allows Viper to use the config/env value if the flag is omitted.
	scanCmd.Flags().IntP("depth", "d", 0, "Maximum crawl depth. (Overrides config/env)")
	viper.BindPFlag("discovery.max_depth", scanCmd.Flags().Lookup("depth"))

	// Using -j (jobs) as -c is used for --config
	scanCmd.Flags().IntP("concurrency", "j", 0, "Number of concurrent engine workers. (Overrides config/env)")
	// Bind the "concurrency" flag to the "engine.worker_concurrency" config key
	viper.BindPFlag("engine.worker_concurrency", scanCmd.Flags().Lookup("concurrency"))

	return scanCmd
}

// scanComponents holds initialized services.
type scanComponents struct {
	Store          *store.Store
	BrowserManager schemas.BrowserManager
	KnowledgeGraph schemas.KnowledgeGraphClient
	TaskEngine     schemas.TaskEngine
	DiscoveryEngine schemas.DiscoveryEngine
	Orchestrator   *orchestrator.Orchestrator
	DBPool         *pgxpool.Pool
}

// Shutdown gracefully closes all components.
func (sc *scanComponents) Shutdown(ctx context.Context) {
	// Use a background context with timeout for shutdown procedures.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if sc.TaskEngine != nil {
		sc.TaskEngine.Stop()
	}
	if sc.DiscoveryEngine != nil {
		sc.DiscoveryEngine.Stop()
	}
	if sc.BrowserManager != nil {
		if err := sc.BrowserManager.Shutdown(shutdownCtx); err != nil {
			observability.GetLogger().Warn("Error during browser manager shutdown", zap.Error(err))
		}
	}
	if sc.DBPool != nil {
		sc.DBPool.Close()
	}
}

// initializeScanComponents handles dependency injection.
// Note: This implementation assumes the structure of internal/config/config.go matches the usage (e.g., cfg.Discovery, cfg.Engine).
func initializeScanComponents(ctx context.Context, cfg *config.Config, targets []string, logger *zap.Logger) (*scanComponents, error) {
	components := &scanComponents{}

	// 1. Database and Store
	if cfg.Database.URL == "" {
		return nil, fmt.Errorf("database URL is not configured (SCALPEL_DATABASE_URL)")
	}
	dbPool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	components.DBPool = dbPool

	dbStore, err := store.New(ctx, dbPool, logger)
	if err != nil {
		return components, fmt.Errorf("failed to initialize database store: %w", err)
	}
	components.Store = dbStore

	// 2. Browser Manager
	browserManager, err := browser.NewManager(ctx, logger, cfg)
	if err != nil {
		return components, fmt.Errorf("failed to initialize browser manager: %w", err)
	}
	components.BrowserManager = browserManager

	// 3. Knowledge Graph
	kg, err := agent.NewGraphStoreFromConfig(ctx, cfg.Agent.KnowledgeGraph, dbPool, logger)
	if err != nil {
		return components, fmt.Errorf("failed to initialize knowledge graph store: %w", err)
	}
	components.KnowledgeGraph = kg

	// 4. Task Engine (This uses the configuration which includes the Gemini API Key if provided)
	taskEngine, err := engine.New(cfg, logger, dbStore, browserManager, kg)
	if err != nil {
		return components, fmt.Errorf("failed to initialize task engine: %w", err)
	}
	components.TaskEngine = taskEngine

	// 5. Discovery Engine
	scopeManager, err := discovery.NewBasicScopeManager(targets[0], cfg.Discovery.IncludeSubdomains)
	if err != nil {
		return components, fmt.Errorf("failed to initialize scope manager: %w", err)
	}

	httpClient := network.NewClient(nil)
	httpAdapter := discovery.NewHTTPClientAdapter(httpClient)

	// Manually construct the discovery.Config struct from the main config values.
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
	components.DiscoveryEngine = discoveryEngine

	// 6. Orchestrator
	orch, err := orchestrator.New(cfg, logger, discoveryEngine, taskEngine)
	if err != nil {
		return components, fmt.Errorf("failed to create orchestrator: %w", err)
	}
	components.Orchestrator = orch

	return components, nil
}

// generateReport handles result processing and report writing.
func generateReport(ctx context.Context, dbStore *store.Store, scanID, format, outputPath string, logger *zap.Logger) error {
	logger.Info("Generating scan report...", zap.String("format", format), zap.String("output_path", outputPath))

	reporter, err := reporting.New(format, outputPath, logger, Version)
	if err != nil {
		return fmt.Errorf("failed to initialize reporter: %w", err)
	}
	defer func() {
		if err := reporter.Close(); err != nil {
			logger.Error("Failed to close reporter", zap.Error(err))
		}
	}()

	pipeline := results.NewPipeline(dbStore, logger)
	processedResults, err := pipeline.ProcessScanResults(ctx, scanID)
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